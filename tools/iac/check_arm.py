"""IaC test of infra/bicep (06 «Ресурсы»): the compiled ARM template is checked for both environments, prod and test.

  python3 -I tools/iac/check_arm.py                      # builds infra/bicep/main.bicep with «az bicep build»
  python3 -I tools/iac/check_arm.py --template arm.json  # checks a prebuilt ARM template
  python3 -I tools/iac/check_arm.py --self-test          # every check must fail on a deliberately broken copy

Conditions, copy counts, module parameters and settings go through the small ARM expression evaluator of arm_eval.py.
Values that exist only at deployment time (reference(), uniqueString(), the subscription in a resource id) stay
unknown: a check that needs such a value fails, and a function the evaluator does not know stops with «cannot evaluate»
instead of a guess. The checks of the restore path (RB-05) are in restore_checks.py, shared helpers in iac_common.py.
Standard library only.
"""
import argparse
import copy
import json
import pathlib
import re
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from arm_eval import (  # noqa: E402
    MISSING, CannotEvaluate, Context, concrete, is_deployment, is_int, known_end, known_start, literals, origins,
    raw_resources, resource_list, show)
from iac_common import (  # noqa: E402
    AZ, MUTATIONS, Failed, commands, identities_of, mutation, one_or_more, raw_of, replace_text, set_value, settings_of)
import restore_checks  # noqa: E402
import deployment_checks  # noqa: E402

# Records of development-package/specs/invariants.json (enforcement «infra») that these checks enforce.
INVARIANTS = ("INV-081", "INV-083", "INV-085")

ROOT = pathlib.Path(__file__).resolve().parents[2]
MAIN = ROOT / 'infra' / 'bicep' / 'main.bicep'
SETUP = ROOT / 'infra' / 'scripts' / 'setup.sh'
DEPLOY = ROOT / 'infra' / 'scripts' / 'deploy-app.sh'
DRILL = ROOT / 'infra' / 'scripts' / 'drill.sh'
ENVIRONMENTS = ('prod', 'test')
CONTAINERS = ('agent-releases', 'dataprotection', 'exports', 'reports', 'security-log')
ORPHAN_PREFIXES = ('reports/restore-orphans/', 'exports/restore-orphans/')
SECRET_MARKERS = ('Password=', 'AccountKey=', 'SharedAccessSignature')
KEY_VAULT_SETTINGS = ('Cursors__Key', 'Agents__NonceKey', 'Teams__WebhookUrl')


# --- Checks of the template --------------------------------------------------------------------------------------

def check_storage_access(ctx):
    accounts = one_or_more(ctx, 'Microsoft.Storage/storageAccounts', 'storage account')
    for account in accounts:
        for key in ('allowSharedKeyAccess', 'allowBlobPublicAccess'):
            value = account.get('properties', key)
            if value is not False:
                raise Failed(f'{key} is {show(value)}, must be false')
    return 'allowSharedKeyAccess and allowBlobPublicAccess are false'


def check_containers(ctx):
    names = []
    for container in ctx.of('Microsoft.Storage/storageAccounts/blobServices/containers'):
        name = (container.segments(1) or (None,))[0]
        if name is None:
            raise Failed(f'cannot evaluate the container name {show(container.name)}')
        access = container.get('properties', 'publicAccess')
        if access != 'None':
            raise Failed(f'container {name}: publicAccess is {show(access)}, must be None')
        names.append(name)
    if sorted(names) != list(CONTAINERS):
        raise Failed(f'containers are {sorted(names)}, expected {list(CONTAINERS)}')
    return f'{", ".join(CONTAINERS)}; publicAccess None'


def check_soft_delete(ctx):
    for service in one_or_more(ctx, 'Microsoft.Storage/storageAccounts/blobServices', 'blob service'):
        for key in ('deleteRetentionPolicy', 'containerDeleteRetentionPolicy'):
            enabled, days = service.get('properties', key, 'enabled'), service.get('properties', key, 'days')
            if enabled is not True or not is_int(days) or days != 7:
                raise Failed(f'{key} is enabled={show(enabled)} days={show(days)}, expected enabled for 7 days')
    return 'blob and container soft delete enabled for 7 days'


def check_immutability(ctx):
    policies = [policy for policy in ctx.of('Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies')
                if (policy.segments(2) or ('',))[0] == 'security-log']
    if len(policies) != 1:
        raise Failed(f'{len(policies)} immutability policies on security-log, expected 1')
    days = policies[0].get('properties', 'immutabilityPeriodSinceCreationInDays')
    appends = [policies[0].get('properties', key) for key in ('allowProtectedAppendWrites', 'allowProtectedAppendWritesAll')]
    if not is_int(days) or days != 30:
        raise Failed(f'immutabilityPeriodSinceCreationInDays is {show(days)}, expected 30')
    if appends[0] is not False or appends[1] not in (False, MISSING):
        raise Failed(f'protected append writes are {show(appends[0])}/{show(appends[1])}, expected false')
    return 'security-log: time-based immutability 30 days, no protected append writes'


def lifecycle_rules(ctx):
    rules = []
    for policy in ctx.of('Microsoft.Storage/storageAccounts/managementPolicies'):
        value = policy.get('properties', 'policy', 'rules')
        if not isinstance(value, list) or not concrete(value):
            raise Failed(f'cannot evaluate the lifecycle rules: {show(value)}')
        rules += [rule for rule in value if rule.get('enabled', True) is True and rule.get('type', 'Lifecycle') == 'Lifecycle']
    return rules


def prefixes(rule):
    return ((rule.get('definition') or {}).get('filters') or {}).get('prefixMatch') or []


def deletion_days(rule):
    """Days after which the rule deletes base block blobs, or None."""
    definition = rule.get('definition') or {}
    if 'blockBlob' not in ((definition.get('filters') or {}).get('blobTypes') or []):
        return None
    delete = ((definition.get('actions') or {}).get('baseBlob') or {}).get('delete') or {}
    days = [delete[key] for key in ('daysAfterCreationGreaterThan', 'daysAfterModificationGreaterThan',
                                    'daysAfterLastAccessTimeGreaterThan') if key in delete]
    return min(days) if days else None


def earliest_deletion(rules, prefix):
    """The earliest age at which any rule deletes some blob under prefix."""
    days = [deletion_days(rule) for rule in rules if deletion_days(rule) is not None
            and (not prefixes(rule) or any(p.startswith(prefix) or prefix.startswith(p) for p in prefixes(rule)))]
    return min(days) if days else None


def check_security_log_lifecycle(ctx):
    rules = lifecycle_rules(ctx)
    if not any(deletion_days(rule) is not None and any('security-log/'.startswith(p) for p in prefixes(rule) or [''])
               for rule in rules):
        raise Failed('no lifecycle rule deletes the security-log/ blobs')
    earliest = earliest_deletion(rules, 'security-log/')
    if earliest <= 30:
        raise Failed(f'security-log/ blobs are deleted after {earliest} days, within the 30-day immutability')
    return f'security-log/ blobs are deleted after {earliest} days'


def check_orphans(ctx):
    rules = lifecycle_rules(ctx)
    for prefix in ORPHAN_PREFIXES:
        exact = [deletion_days(rule) for rule in rules if prefix in prefixes(rule) and deletion_days(rule) is not None
                 and not (rule['definition'].get('filters') or {}).get('blobIndexMatch')]
        if not exact:
            raise Failed(f'no lifecycle rule deletes {prefix} blobs')
        earliest = earliest_deletion(rules, prefix)
        if min(exact) != 30 or earliest != 30:
            raise Failed(f'{prefix} blobs are deleted after {earliest} days, expected 30')
    return f'{" and ".join(ORPHAN_PREFIXES)} blobs are deleted after 30 days'


def database_servers(ctx):
    return one_or_more(ctx, 'Microsoft.DBforPostgreSQL/flexibleServers', 'PostgreSQL flexible server')


def check_database_network(ctx):
    for server in database_servers(ctx):
        access = server.get('properties', 'network', 'publicNetworkAccess')
        subnet = server.get('properties', 'network', 'delegatedSubnetResourceId')
        if access != 'Disabled':
            raise Failed(f'publicNetworkAccess is {show(access)}, must be Disabled')
        if subnet is MISSING or subnet in (None, ''):
            raise Failed('no delegatedSubnetResourceId: the server is not in the VNet')
    return 'publicNetworkAccess Disabled, delegated subnet of the VNet'


def check_firewall(ctx):
    rules = [kind for kind, _ in raw_resources(ctx.template)
             if kind.lower().startswith('microsoft.dbforpostgresql/') and kind.lower().endswith('/firewallrules')]
    if rules:
        raise Failed(f'{len(rules)} firewall rule resources: {rules[0]}')
    return 'no firewallRules resources anywhere in the template'


def check_database_auth(ctx):
    for server in database_servers(ctx):
        password = server.get('properties', 'authConfig', 'passwordAuth')
        entra = server.get('properties', 'authConfig', 'activeDirectoryAuth')
        if password != 'Disabled' or entra != 'Enabled':
            raise Failed(f'passwordAuth {show(password)}, activeDirectoryAuth {show(entra)}: expected Entra sign-in only')
    return 'passwordAuth Disabled, activeDirectoryAuth Enabled'


def check_database_backup(ctx):
    for server in database_servers(ctx):
        days = server.get('properties', 'backup', 'backupRetentionDays')
        if not is_int(days) or days != 14:
            raise Failed(f'backupRetentionDays is {show(days)}, expected 14')
    return 'point-in-time restore 14 days'


def check_migrations_identity(ctx):
    found = [identity for identity in ctx.of('Microsoft.ManagedIdentity/userAssignedIdentities')
             if (identity.segments(1) or ('',))[0].endswith('-migrations')]
    if len(found) != 1:
        raise Failed(f'{len(found)} migrations identities, expected 1')
    name = found[0].segments(1)[0].lower()
    carriers = [resource for resource in ctx.resources if name in identities_of(resource)]
    for site in ctx.of('Microsoft.Web/sites'):
        kind = site.get('identity', 'type')
        if not isinstance(kind, str) or 'systemassigned' not in kind.lower().replace(' ', '').split(','):
            raise Failed(f'the production site identity is {show(kind)}, expected SystemAssigned')
    names = [carrier.describe() for carrier in carriers] or ['nothing']
    if ctx.environment == 'prod':
        if len(carriers) != 1 or carriers[0].type.lower() != 'microsoft.web/sites/slots' \
                or carriers[0].segments(1) != ('staging',):
            raise Failed(f'the migrations identity is on {", ".join(names)}, expected only the staging slot')
        return 'the migrations identity is on the staging slot only; the site signs in with its SystemAssigned identity'
    slots = ctx.of('Microsoft.Web/sites/slots')
    if slots or carriers:
        raise Failed(f'{len(slots)} slot(s) deployed, the migrations identity is on {", ".join(names)}: expected none')
    return 'no slot and no resource with the migrations identity (assigned only during a deployment)'


def check_jobs(ctx):
    production = [r for r in ctx.of('Microsoft.Web/sites/config') if r.segments(1) == ('appsettings',)]
    slots = [r for r in ctx.of('Microsoft.Web/sites/slots/config') if r.segments(1) == ('appsettings',)]
    staging = [r for r in slots if r.segments(2) == ('staging', 'appsettings')]
    if len(production) != 1:
        raise Failed(f'{len(production)} production app settings resources, expected 1')
    expected = [('production', settings_of(production[0]), 'true', 'false')]
    if ctx.environment == 'prod':
        if len(staging) != 1:
            raise Failed(f'{len(staging)} app settings resources of the staging slot, expected 1')
        expected.append(('staging', settings_of(staging[0]), 'false', 'true'))
    elif slots:
        raise Failed(f'{len(slots)} slot settings in an environment without slots')
    for slot in slots:
        if slot not in staging and settings_of(slot).get('Jobs__Enabled') != 'false':
            raise Failed(f'{slot.describe()} does not disable jobs')
    for where, settings, jobs, migrate in expected:
        for key, wanted in (('Jobs__Enabled', jobs), ('Database__MigrateOnStart', migrate)):
            if settings.get(key, MISSING) != wanted:
                raise Failed(f'{where} {key} is {show(settings.get(key, MISSING))}, expected {wanted!r}')
    if ctx.environment != 'prod':
        return 'the single app runs jobs and does not migrate at start'
    sticky = [r for r in ctx.of('Microsoft.Web/sites/config') if r.segments(1) == ('slotConfigNames',)]
    names = sticky[0].get('properties', 'appSettingNames') if len(sticky) == 1 else MISSING
    for key in ('Jobs__Enabled', 'Database__MigrateOnStart'):
        if not isinstance(names, list) or key not in names:
            raise Failed(f'{key} is not a slot setting (slotConfigNames)')
    return 'production: jobs on, migrations off; staging: jobs off, migrations on; both settings stay with their slot'


def setting_sources(ctx):
    """(where, kind, value) of every app settings and connection strings resource and inline siteConfig settings."""
    sources = []
    for kind in ('Microsoft.Web/sites/config', 'Microsoft.Web/sites/slots/config'):
        for resource in ctx.of(kind):
            section = (resource.segments(1) or ('',))[0].lower()
            if section in ('appsettings', 'connectionstrings'):
                sources.append((resource.describe(), section, resource.get('properties')))
    for kind in ('Microsoft.Web/sites', 'Microsoft.Web/sites/slots'):
        for resource in ctx.of(kind):
            for key in ('appSettings', 'connectionStrings'):
                value = resource.get('properties', 'siteConfig', key)
                if value is not MISSING:
                    sources.append((f'{resource.describe()} siteConfig', key.lower(), value))
    return sources


def check_secrets(ctx):
    count = 0
    for where, kind, value in setting_sources(ctx):
        for literal in literals(value):
            for marker in SECRET_MARKERS:
                if marker.lower() in literal.lower():
                    raise Failed(f'{where}: a value contains {marker}')
        for origin in origins(value):
            if origin.lower().startswith('list'):
                raise Failed(f'{where}: a value comes from {origin}()')
        if kind == 'appsettings' and isinstance(value, dict):
            count += 1
            for name in KEY_VAULT_SETTINGS:
                setting = value.get(name, MISSING)
                if not (known_start(setting).startswith('@Microsoft.KeyVault(') and known_end(setting).endswith(')')):
                    raise Failed(f'{where}: {name} is {show(setting)}, not a Key Vault reference')
        elif kind == 'appsettings':
            raise Failed(f'cannot evaluate {where}: {show(value)}')
    if not count:
        raise Failed('no app settings')
    return f'{count} app settings resources: no secret values; {" and ".join(KEY_VAULT_SETTINGS)} from Key Vault'


# --- Checks of the scripts (locking and slot stops cannot be expressed in ARM) -----------------------------------

LOCK = re.compile(AZ + r"storage\s+container\s+immutability-policy\s+lock\b.*(?:--container-name|-c)\s+[\"']?security-log\b")
SWAP = re.compile(AZ + r'webapp\s+deployment\s+slot\s+swap\b')
STOP = re.compile(AZ + r"webapp\s+stop\b.*--slot\s+[\"']?staging\b")


def check_setup_lock(scripts):
    if not any(LOCK.search(line) for line in commands(scripts['setup'])):
        raise Failed('setup.sh has no «az storage container immutability-policy lock» for security-log')
    return 'setup.sh locks the security-log immutability policy (locking is not expressible in ARM)'


def check_deploy_stop(scripts):
    lines = commands(scripts['deploy'])
    swaps = [index for index, line in enumerate(lines) if SWAP.search(line)]
    if not swaps:
        raise Failed('deploy-app.sh has no «az webapp deployment slot swap»')
    if not any(STOP.search(line) for line in lines[swaps[0] + 1:]):
        raise Failed('deploy-app.sh does not run «az webapp stop --slot staging» after the swap')
    return 'deploy-app.sh stops the staging slot after the swap'


CHECKS = (
    ('storage keys and public access', None, check_storage_access),
    ('private containers', None, check_containers),
    ('blob soft delete', None, check_soft_delete),
    ('security-log immutability', 'INV-083', check_immutability),
    ('security-log lifecycle', 'INV-083', check_security_log_lifecycle),
    ('restore-orphans lifecycle', 'INV-081', check_orphans),
    ('database network', None, check_database_network),
    ('database firewall rules', None, check_firewall),
    ('database sign-in', None, check_database_auth),
    ('database backup', None, check_database_backup),
    ('migrations identity', None, check_migrations_identity),
    ('jobs only in the production slot', 'INV-085', check_jobs),
    ('no secrets in settings', None, check_secrets),
) + restore_checks.CHECKS + deployment_checks.CHECKS
SCRIPT_CHECKS = (
    ('setup.sh locks security-log', 'INV-083', check_setup_lock),
    ('deploy stops staging after swap', 'INV-085', check_deploy_stop),
) + restore_checks.SCRIPT_CHECKS + deployment_checks.SCRIPT_CHECKS


def attempt(check, subject):
    try:
        return True, check(subject)
    except Failed as failure:
        return False, str(failure)
    except CannotEvaluate as error:
        return False, f'cannot evaluate: {error}'


def run(template, scripts):
    """(label, title, invariant, ok, reason) of every check."""
    results = []
    for environment in ENVIRONMENTS:
        try:
            ctx = Context(template, environment)
        except (CannotEvaluate, RecursionError) as error:
            results.append((environment, 'template', None, False, f'cannot evaluate: {error}'))
            continue
        for title, invariant, check in CHECKS:
            results.append((environment, title, invariant, *attempt(check, ctx)))
    for title, invariant, check in SCRIPT_CHECKS:
        results.append(('scripts', title, invariant, *attempt(check, scripts)))
    return results


def line(result):
    label, title, invariant, ok, reason = result
    return f'{"PASS" if ok else "FAIL"} [{label}] {title}{f" ({invariant})" if invariant else ""}: {reason}'


# --- Self-test: deliberately broken copies must fail (helpers and registry in iac_common.py) --------------------

def rules_of(template, prefix):
    return [rule for raw in raw_of(template, 'Microsoft.Storage/storageAccounts/managementPolicies')
            for rule in raw['properties']['policy']['rules'] if prefix in prefixes(rule)]


def set_days(template, prefix, days):
    rules = rules_of(template, prefix)
    for rule in rules:
        rule['definition']['actions']['baseBlob']['delete']['daysAfterCreationGreaterThan'] = days
    return len(rules)


SA, CONTAINER = 'Microsoft.Storage/storageAccounts', 'Microsoft.Storage/storageAccounts/blobServices/containers'
POLICY, PSQL = f'{CONTAINER}/immutabilityPolicies', 'Microsoft.DBforPostgreSQL/flexibleServers'

mutation('prod', 'storage keys and public access', 'allowSharedKeyAccess true')(
    lambda t, s: set_value(t, SA, ('properties', 'allowSharedKeyAccess'), True))
mutation('test', 'storage keys and public access', 'allowBlobPublicAccess true')(
    lambda t, s: set_value(t, SA, ('properties', 'allowBlobPublicAccess'), True))
mutation('prod', 'private containers', 'a public container')(
    lambda t, s: set_value(t, CONTAINER, ('properties', 'publicAccess'), 'Blob'))
mutation('prod', 'private containers', 'container agent-releases missing')(
    lambda t, s: replace_text(t, "'agent-releases', ", ''))
mutation('prod', 'blob soft delete', 'blob soft delete 1 day')(
    lambda t, s: set_value(t, f'{SA}/blobServices', ('properties', 'deleteRetentionPolicy', 'days'), 1))
mutation('prod', 'security-log immutability', 'immutability 7 days')(
    lambda t, s: set_value(t, POLICY, ('properties', 'immutabilityPeriodSinceCreationInDays'), 7))
mutation('test', 'security-log immutability', 'protected append writes allowed')(
    lambda t, s: set_value(t, POLICY, ('properties', 'allowProtectedAppendWrites'), True))
mutation('prod', 'security-log lifecycle', 'security-log deleted after 20 days')(
    lambda t, s: set_days(t, 'security-log/', 20))
mutation('prod', 'restore-orphans lifecycle', 'restore-orphans kept 90 days')(
    lambda t, s: set_days(t, ORPHAN_PREFIXES[0], 90))
mutation('test', 'restore-orphans lifecycle', 'exports/restore-orphans/ without a rule')(
    lambda t, s: replace_text(t, f'"{ORPHAN_PREFIXES[1]}"', '"exports/other/"'))
mutation('prod', 'database network', 'publicNetworkAccess Enabled')(
    lambda t, s: set_value(t, PSQL, ('properties', 'network', 'publicNetworkAccess'), 'Enabled'))
mutation('test', 'database sign-in', 'password sign-in enabled')(
    lambda t, s: set_value(t, PSQL, ('properties', 'authConfig', 'passwordAuth'), 'Enabled'))
mutation('prod', 'database backup', 'backup retention 7 days')(
    lambda t, s: set_value(t, PSQL, ('properties', 'backup', 'backupRetentionDays'), 7))
mutation('prod', 'migrations identity', 'migrations identity on the production site')(
    lambda t, s: set_value(t, 'Microsoft.Web/sites', ('identity',), {
        'type': 'SystemAssigned, UserAssigned',
        'userAssignedIdentities': {"[format('{0}', parameters('migrationsIdentityId'))]": {}}}))
mutation('test', 'migrations identity', 'staging slot deployed in test')(
    lambda t, s: set_value(t, 'Microsoft.Web/sites/slots', ('condition',), '[true()]'))
mutation('prod', 'jobs only in the production slot', 'Jobs__Enabled true on staging')(
    lambda t, s: replace_text(t, "'Jobs__Enabled', 'false'", "'Jobs__Enabled', 'true'"))
mutation('prod', 'jobs only in the production slot', 'Database__MigrateOnStart true in production')(
    lambda t, s: replace_text(t, "'Database__MigrateOnStart', 'false'", "'Database__MigrateOnStart', 'true'"))
mutation('prod', 'no secrets in settings', 'a password in the app settings')(
    lambda t, s: replace_text(t, "'Database__MigrateOnStart', 'false'",
                              "'Database__MigrateOnStart', 'false', 'Legacy', 'Host=db;Password=secret'"))
mutation('test', 'no secrets in settings', 'Cursors__Key as a plain value')(
    lambda t, s: replace_text(t, '@Microsoft.KeyVault(VaultName={0};SecretName=cursor-key)', 'plain-{0}'))
mutation('prod', 'template', 'unsupported function in a condition')(
    lambda t, s: set_value(t, 'Microsoft.Web/sites/slots', ('condition',), "[contains(parameters('name'), 'x')]"))


@mutation('prod', 'database firewall rules', 'a firewall rule on the server')
def add_firewall_rule(template, scripts):
    for full, raw in raw_resources(template):
        if is_deployment(raw) and any(str(r.get('type')).lower() == PSQL.lower()
                                      for r in resource_list(raw['properties']['template'])):
            raw['properties']['template']['resources'].append({
                'type': f'{PSQL}/firewallRules', 'apiVersion': '2024-08-01', 'name': 'any',
                'properties': {'startIpAddress': '0.0.0.0', 'endIpAddress': '255.255.255.255'}})
            return 1
    return 0


@mutation('prod', 'jobs only in the production slot', 'Jobs__Enabled not a slot setting')
def unstick_jobs(template, scripts):
    count = 0
    for raw in raw_of(template, 'Microsoft.Web/sites/config'):
        names = (raw.get('properties') or {}).get('appSettingNames') if isinstance(raw.get('properties'), dict) else None
        if isinstance(names, list) and 'Jobs__Enabled' in names:
            names.remove('Jobs__Enabled')
            count += 1
    return count


@mutation('scripts', 'setup.sh locks security-log', 'setup.sh without the lock')
def drop_lock(template, scripts):
    count = scripts['setup'].count('immutability-policy lock')
    scripts['setup'] = scripts['setup'].replace('immutability-policy lock', 'immutability-policy show')
    return count


@mutation('scripts', 'deploy stops staging after swap', 'deploy-app.sh without stopping staging')
def drop_stop(template, scripts):
    scripts['deploy'], count = re.subn(r'az webapp stop[^\n]*', 'true', scripts['deploy'])
    return count


def self_test(template, scripts):
    failed = [result for result in run(template, scripts) if not result[3]]
    for result in failed:
        print(line(result))
    if failed:
        print('Self-test not run: the unmodified template must pass every check first.')
        return 1
    problems = 0
    for description, label, title, function in MUTATIONS:
        broken, texts = copy.deepcopy(template), dict(scripts)
        if not function(broken, texts):
            print(f'FAIL «{description}»: the mutation found nothing to change; update the self-test')
            problems += 1
            continue
        hit = [result for result in run(broken, texts) if result[0] == label and result[1] == title]
        if not hit or hit[0][3]:
            print(f'FAIL «{description}»: [{label}] {title} still passes')
            problems += 1
        else:
            print(f'ok   «{description}» → {line(hit[0])}')
    print(f'Self-test: {len(MUTATIONS) - problems} of {len(MUTATIONS)} broken templates were rejected.')
    return 1 if problems else 0


# --- Entry point -------------------------------------------------------------------------------------------------

DIAGNOSTIC = re.compile(r'\(\d+,\d+\) : (?:Warning|Error) ')


def build():
    """Compiles main.bicep; returns the ARM template and the Bicep warnings."""
    try:
        result = subprocess.run(['az', 'bicep', 'build', '--file', str(MAIN), '--stdout'],
                                capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise RuntimeError('az is not installed; pass --template with a prebuilt ARM template') from None
    if result.returncode != 0:
        raise RuntimeError(f'az bicep build failed: {result.stderr.strip()[-2000:]}')
    warnings = [entry.strip() for entry in result.stderr.splitlines() if DIAGNOSTIC.search(entry)]
    return json.loads(result.stdout), warnings


def main(argv=None):
    parser = argparse.ArgumentParser(description='IaC test of infra/bicep for the prod and test environments.')
    parser.add_argument('--template', type=pathlib.Path, help='a prebuilt ARM template instead of «az bicep build»')
    parser.add_argument('--self-test', action='store_true', help='check that deliberately broken copies fail')
    args = parser.parse_args(argv)
    results = []
    try:
        if args.template:
            template = json.loads(args.template.read_text(encoding='utf-8'))
        else:
            template, warnings = build()
            results.append(('build', 'bicep build without warnings', None, not warnings,
                            warnings[0] if warnings else str(MAIN.relative_to(ROOT))))
        scripts = {name: path.read_text(encoding='utf-8') for name, path in
                   (('setup', SETUP), ('deploy', DEPLOY), ('drill', DRILL))}
    except (OSError, ValueError, RuntimeError) as error:
        print(f'FAIL [build] {error}')
        return 1
    if args.self_test:
        return self_test(template, scripts)
    print(f'IaC check of the ARM template for {", ".join(ENVIRONMENTS)}; invariants {", ".join(INVARIANTS)}')
    results += run(template, scripts)
    for result in results:
        print(line(result))
    failures = sum(1 for result in results if not result[3])
    print(f'{len(results) - failures} passed, {failures} failed.')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
