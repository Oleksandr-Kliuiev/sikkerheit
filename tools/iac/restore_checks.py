"""IaC checks of the restore path (RB-05, 04 «Журнал безопасности»), run by check_arm.py: the restore identity only
reads the security log and the files, the database server is a parameter that setup.sh fills from the app after a
restore, and drill.sh changes nothing in production. Each check has deliberately broken copies for --self-test.
"""
import itertools
import re

from arm_eval import MISSING, Context, Partial, Unknown, known_end, known_start, literals, raw_resources, show, text
from iac_common import (
    Failed, commands, identities_of, mutation, one_or_more, raw_of, replace_script, replace_text, set_value, settings_of)

READER = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'  # Storage Blob Data Reader
CONTRIBUTOR = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'  # Storage Blob Data Contributor
RESTORE_CONTAINERS = ('exports', 'reports', 'security-log')
RESTORE_SETTING = 'Restore__ManagedIdentityClientId'
PSQL = 'Microsoft.DBforPostgreSQL/flexibleServers'
RESTORED = 'psql-sikkerheit-{}-restored'  # a server name as setup.sh passes it after a restore


def restore_identity(ctx):
    found = [identity for identity in ctx.of('Microsoft.ManagedIdentity/userAssignedIdentities')
             if (identity.segments(1) or ('',))[0].endswith('-restore')]
    if len(found) != 1:
        raise Failed(f'{len(found)} restore identities, expected 1')
    return found[0].segments(1)[0].lower()


def refers_to(value, kind, name, prop):
    """True when the value is reference() of the resource kind/name, then .prop."""
    return isinstance(value, Unknown) and value.origin == 'reference' \
        and value.source.lower().endswith(f'/{kind}/{name}.{prop}'.lower())


def app_settings(ctx, kind):
    return [(resource, settings_of(resource)) for resource in ctx.of(kind) if resource.segments(1) == ('appsettings',)]


def check_restore_identity(ctx):
    name = restore_identity(ctx)
    carriers = [resource for resource in ctx.resources if name in identities_of(resource)]
    if [carrier.type.lower() for carrier in carriers] != ['microsoft.web/sites']:
        raise Failed(f'{name} is on {", ".join(c.describe() for c in carriers) or "nothing"}, expected only the production site')
    others = [identity for identity in identities_of(carriers[0]) if identity != name]
    if others:
        raise Failed(f'the production site also has {", ".join(others)}')
    production = app_settings(ctx, 'Microsoft.Web/sites/config')
    if len(production) != 1:
        raise Failed(f'{len(production)} production app settings resources, expected 1')
    value = production[0][1].get(RESTORE_SETTING, MISSING)
    if not refers_to(value, 'userAssignedIdentities', name, 'clientId'):
        raise Failed(f'production {RESTORE_SETTING} is {show(value)}, expected the clientId of {name}')
    for slot, settings in app_settings(ctx, 'Microsoft.Web/sites/slots/config'):
        if RESTORE_SETTING in settings:
            raise Failed(f'{slot.describe()} has {RESTORE_SETTING}: the restore command runs in the production slot only')
    if ctx.environment != 'prod':
        return f'{name} is on the app only, which names it in {RESTORE_SETTING}'
    sticky = [r for r in ctx.of('Microsoft.Web/sites/config') if r.segments(1) == ('slotConfigNames',)]
    names = sticky[0].get('properties', 'appSettingNames') if len(sticky) == 1 else MISSING
    if not isinstance(names, list) or RESTORE_SETTING not in names:
        raise Failed(f'{RESTORE_SETTING} is not a slot setting (slotConfigNames): a swap would take it from production')
    return f'{name} is on the production slot only, which names it in {RESTORE_SETTING}, a slot setting'


def check_restore_access(ctx):
    name = restore_identity(ctx)
    grants = [grant for grant in ctx.of('Microsoft.Authorization/roleAssignments')
              if refers_to(grant.get('properties', 'principalId'), 'userAssignedIdentities', name, 'principalId')]
    containers = []
    for grant in grants:
        role = known_end(grant.get('properties', 'roleDefinitionId')).lower()
        if not role.endswith(f'/roledefinitions/{READER}'):
            raise Failed(f'{name} has the role {role.rsplit("/", 1)[-1] or "?"}, expected only Storage Blob Data Reader')
        scope = grant.get('scope')
        path = ''.join(literals(scope)).lower()
        match = re.search(r'/blobservices/default/containers/([^/]+)$', known_end(scope).lower())
        if '/providers/microsoft.storage/storageaccounts/' not in path or not match:
            raise Failed(f'{name} reads at {show(scope)}: expected the scope of single containers')
        containers.append(match.group(1))
    if sorted(containers) != list(RESTORE_CONTAINERS):
        raise Failed(f'{name} reads {sorted(containers) or "nothing"}, expected {list(RESTORE_CONTAINERS)}')
    return f'{name}: Storage Blob Data Reader on {", ".join(RESTORE_CONTAINERS)} only'


def same_text(left, right):
    """Equal strings; strings with deployment-time parts must share those parts (the same evaluation)."""
    if not (isinstance(left, Partial) and isinstance(right, Partial)):
        return left == right
    return len(left.parts) == len(right.parts) and all(
        a == b if isinstance(a, str) else a is b for a, b in zip(left.parts, right.parts))


def check_database_server(ctx):
    servers = one_or_more(ctx, PSQL, 'PostgreSQL flexible server')
    expected = text(['psql-', ctx.scope.variable('unique')])
    if len(servers) != 1 or not same_text(servers[0].name, expected):
        raise Failed(f'the default server is {show([s.name for s in servers])}, expected {show(expected)}: '
                     'a deployment would create a new, empty server')
    restored = RESTORED.format(ctx.environment)
    other = Context(ctx.template, ctx.environment, {'databaseServerName': restored})
    names = [server.name for server in other.of(PSQL)]
    if names != [restored]:
        raise Failed(f'with databaseServerName={restored} the servers are {show(names)}, expected only {restored}')
    count = 0
    for resource, settings in app_settings(other, 'Microsoft.Web/sites/config') + \
            app_settings(other, 'Microsoft.Web/sites/slots/config'):
        for key, value in settings.items():
            if not key.startswith('ConnectionStrings__'):
                continue
            hosts = value.parts[1:2] if isinstance(value, Partial) and known_start(value) == 'Host=' else []
            if not (hosts and refers_to(hosts[0], 'flexibleServers', restored, 'fullyQualifiedDomainName')):
                raise Failed(f'{resource.describe()} {key} is {show(value)}: the host is not the server of databaseServerName')
            count += 1
    if not count:
        raise Failed('no connection strings in the app settings')
    return f'default psql-<unique>; with databaseServerName the server and the connection strings ({count}) follow it'


CHECKS = (
    ('restore identity on the production slot', None, check_restore_identity),
    ('restore identity reads only', 'INV-081', check_restore_access),
    ('database server parameter', None, check_database_server),
)


# --- Checks of the scripts ---------------------------------------------------------------------------------------

READ_VERBS = {'show', 'list', 'exists', 'download'}
GROUP = re.compile(r'\$\{?group\b')
PRODUCTION = re.compile(r'\$\{?production\b|rg-sikkerheit-prod\b')
# Any az call, wherever it stands: after «|| {», in a case arm, behind xargs. Stricter than AZ of iac_common, which
# skips echo texts: here a false match only makes the check stricter.
AZ_ANYWHERE = re.compile(r'(?<![\w.$-])az\s+')


def az_calls(script):
    """(verb, command) of every az call: the verb is the last word of the command group, such as set in
    «az webapp config appsettings set»; an unreadable group counts as a change."""
    for line in commands(script):
        for match in AZ_ANYWHERE.finditer(line):
            words = itertools.takewhile(lambda word: re.fullmatch(r'[a-z][a-z0-9-]*', word), line[match.end():].split())
            yield ([''] + list(words))[-1], line


def check_setup_server(scripts):
    lines = commands(scripts['setup'])
    if not any('az deployment group create' in line and 'databaseServerName=' in line for line in lines):
        raise Failed('setup.sh does not pass databaseServerName to the deployment')
    if not any('ConnectionStrings__Sikkerheit' in line and 'appsettings list' in line for line in lines):
        raise Failed('setup.sh does not take the server from the connection string of the app')
    if not any(verb == 'show' and 'postgres flexible-server show' in line for verb, line in az_calls(scripts['setup'])):
        raise Failed('setup.sh does not check that the database server exists')
    return 'setup.sh keeps the server of the app (or SIKKERHEIT_DATABASE_SERVER) and refuses an unknown one'


def check_drill_production(scripts):
    lines = commands(scripts['drill'])
    assignments = [line for line in lines if re.match(r'(?:local\s+)?group=', line)]
    if assignments != ['group="rg-sikkerheit-drill"']:
        raise Failed(f'drill.sh sets group as {assignments}, expected only group="rg-sikkerheit-drill"')
    writes = 0
    for verb, line in az_calls(scripts['drill']):
        if verb in READ_VERBS:
            continue
        writes += 1
        if PRODUCTION.search(line) or not GROUP.search(line):
            raise Failed(f'drill.sh changes something outside rg-sikkerheit-drill: «{line[:160]}»')
    if not writes:
        raise Failed('drill.sh has no az commands')
    return f'{writes} az commands change only rg-sikkerheit-drill; production is only read'


def check_drill_replay(scripts):
    replays = [line for line in commands(scripts['drill']) if 'restore-replay' in line]
    if not replays or any('--drill' not in line for line in replays):
        raise Failed('drill.sh runs restore-replay without --drill: the command would move production files')
    deletes = [line for verb, line in az_calls(scripts['drill']) if verb == 'delete' and 'group delete' in line]
    if not any(GROUP.search(line) for line in deletes):
        raise Failed('drill.sh has no «az group delete» of the drill group')
    return 'drill.sh replays with --drill only and deletes rg-sikkerheit-drill on cleanup'


SCRIPT_CHECKS = (
    ('setup.sh keeps the database server', None, check_setup_server),
    ('drill.sh only reads production', None, check_drill_production),
    ('drill.sh lists files and cleans up', 'INV-081', check_drill_replay),
)


# --- Deliberately broken copies ----------------------------------------------------------------------------------

def append_script(scripts, name, text):
    scripts[name] += '\n' + text + '\n'
    return 1


def restore_grants(template):
    return [raw for full, raw in raw_resources(template)
            if full.lower() == 'microsoft.authorization/roleassignments' and 'restorePrincipalId' in str(raw)]


mutation('prod', 'restore identity on the production slot', 'restore identity on the staging slot')(
    lambda t, s: set_value(t, 'Microsoft.Web/sites/slots', ('identity', 'userAssignedIdentities'), {
        "[format('{0}', parameters('migrationsIdentityId'))]": {}, "[format('{0}', parameters('restoreIdentityId'))]": {}}))
mutation('test', 'restore identity on the production slot', 'restore identity missing from the app')(
    lambda t, s: set_value(t, 'Microsoft.Web/sites', ('identity',), {'type': 'SystemAssigned'}))
mutation('prod', 'restore identity on the production slot', 'restore setting with the migrations identity')(
    lambda t, s: replace_text(t, "'Restore__ManagedIdentityClientId', parameters('restoreIdentityClientId')",
                              "'Restore__ManagedIdentityClientId', parameters('migrationsIdentityClientId')"))
mutation('prod', 'restore identity reads only', 'restore identity with Storage Blob Data Contributor')(
    lambda t, s: replace_text(t, READER, CONTRIBUTOR))
mutation('prod', 'restore identity reads only', 'restore identity without security-log')(
    lambda t, s: replace_text(t, '["security-log", "reports", "exports"]', '["reports", "exports"]'))
mutation('prod', 'database server parameter', 'default server renamed')(
    lambda t, s: replace_text(t, "format('psql-{0}', variables('unique'))", "format('pg-{0}', variables('unique'))"))
mutation('test', 'database server parameter', 'databaseServerName ignored')(
    lambda t, s: replace_text(t, "createObject('value', parameters('databaseServerName'))",
                              "createObject('value', format('psql-{0}', variables('unique')))"))
mutation('prod', 'database server parameter', 'connection string with a fixed host')(
    lambda t, s: replace_text(t, "Username=sikkerheit-staging;Ssl Mode=VerifyFull;Maximum Pool Size=10', parameters('databaseHost'))",
                              "Username=sikkerheit-staging;Ssl Mode=VerifyFull;Maximum Pool Size=10', 'psql-old')"))
mutation('scripts', 'setup.sh keeps the database server', 'setup.sh without databaseServerName')(
    lambda t, s: replace_script(s, 'setup', r' databaseServerName="[^"]*"', ''))
mutation('scripts', 'setup.sh keeps the database server', 'setup.sh without the server check')(
    lambda t, s: replace_script(s, 'setup', r'az postgres flexible-server show', 'true'))
mutation('scripts', 'drill.sh only reads production', 'drill.sh changes a production setting')(
    lambda t, s: replace_script(s, 'drill', r'access-restriction set --resource-group "\$group"',
                                'access-restriction set --resource-group "$production"'))
mutation('scripts', 'drill.sh only reads production', 'drill.sh on another group')(
    lambda t, s: replace_script(s, 'drill', r'(?m)^group="rg-sikkerheit-drill"$', 'group="rg-sikkerheit-prod"'))
mutation('scripts', 'drill.sh only reads production', 'drill.sh changes production in an error branch')(
    lambda t, s: append_script(s, 'drill', '[[ -n "$site" ]] || { az webapp config set --resource-group "$production" '
                                           '--name "$site" --always-on false; }'))
mutation('scripts', 'drill.sh only reads production', 'drill.sh stops production through xargs')(
    lambda t, s: append_script(s, 'drill', 'echo "$site" | xargs az webapp stop --resource-group "$production" --name'))
mutation('scripts', 'drill.sh only reads production', 'drill.sh changes production in a case arm')(
    lambda t, s: append_script(s, 'drill', 'case "$mode" in\n  *) az webapp restart --resource-group rg-sikkerheit-prod --name "$site" ;;\nesac'))
mutation('scripts', 'drill.sh lists files and cleans up', 'drill.sh replays without --drill')(
    lambda t, s: replace_script(s, 'drill', r'(restore-replay --since \S+) --drill', r'\1'))
mutation('scripts', 'drill.sh lists files and cleans up', 'drill.sh cleanup keeps the group')(
    lambda t, s: replace_script(s, 'drill', r'az group delete --name "\$group" --yes', 'true'))


@mutation('prod', 'restore identity on the production slot', 'restore setting not a slot setting')
def unstick_restore(template, scripts):
    count = 0
    for raw in raw_of(template, 'Microsoft.Web/sites/config'):
        names = (raw.get('properties') or {}).get('appSettingNames') if isinstance(raw.get('properties'), dict) else None
        if isinstance(names, list) and RESTORE_SETTING in names:
            names.remove(RESTORE_SETTING)
            count += 1
    return count


@mutation('test', 'restore identity reads only', 'restore identity reads the whole account')
def widen_restore(template, scripts):
    grants = restore_grants(template)
    for raw in grants:
        raw['scope'] = "[resourceId('Microsoft.Storage/storageAccounts', parameters('storageAccountName'))]"
    return len(grants)
