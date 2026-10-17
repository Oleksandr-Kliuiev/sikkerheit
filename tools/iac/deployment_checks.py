"""Runtime/deployment parity: production requirements, slot isolation, proxy ingress and agent smoke tests."""
import pathlib
import re

from arm_eval import Context, MISSING, known_end
from iac_common import Failed, mutation, raw_of, replace_script, replace_text, settings_of

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'src/Sikkerheit.Host/Platform/ProductionConfiguration.cs'


def required_keys():
    declaration = SOURCE.read_text().split('RequiredSettings =', 1)[1].split('];', 1)[0]
    return [name.replace(':', '__') for name in re.findall(r'"([\w:]+)"', declaration)]


def app_settings(ctx):
    return [settings_of(r) for kind in ('Microsoft.Web/sites/config', 'Microsoft.Web/sites/slots/config')
            for r in ctx.of(kind) if r.segments(1) == ('appsettings',)]


def check_startup(ctx):
    # The first setup pass deliberately has no app ids; check the second pass, as deployed for the pilot.
    configured = Context(ctx.template, ctx.environment, {'portalClientId': 'portal-client', 'graphClientId': 'graph-client'})
    settings = app_settings(configured)
    if len(settings) != (2 if ctx.environment == 'prod' else 1):
        raise Failed('missing app settings')
    for slot in settings:
        for key in required_keys():
            if slot.get(key, MISSING) in (MISSING, None, ''):
                raise Failed(f'required runtime setting {key} missing or empty')
        if slot.get('ASPNETCORE_FORWARDEDHEADERS_ENABLED') != 'true':
            raise Failed('App Service forwarded client IP and HTTPS scheme are not enabled')
        if slot.get('ASPNETCORE_ENVIRONMENT') != 'Production':
            raise Failed('the deployed app does not use Production validation')
        if slot.get('Jobs__CollectionConcurrency') != '8' or slot.get('Jobs__MaintenanceConcurrency') != '2':
            raise Failed('the deployed job lanes differ from the verified 8 collection / 2 maintenance configuration')
    tuned = Context(ctx.template, ctx.environment, {'portalClientId': 'portal-client', 'graphClientId': 'graph-client',
                                                  'collectionConcurrency': 3, 'maintenanceConcurrency': 1})
    if any(slot.get('Jobs__CollectionConcurrency') != '3' or slot.get('Jobs__MaintenanceConcurrency') != '1'
           for slot in app_settings(tuned)):
        raise Failed('explicit job concurrency parameters do not reach every slot')
    if ctx.environment == 'prod':
        sticky = [r for r in ctx.of('Microsoft.Web/sites/config') if r.segments(1) == ('slotConfigNames',)]
        names = sticky[0].get('properties', 'appSettingNames') if len(sticky) == 1 else []
        if not {'Jobs__CollectionConcurrency', 'Jobs__MaintenanceConcurrency'} <= set(names):
            raise Failed('job concurrency settings must stay with their slot')
    return 'every required runtime setting exists on every slot; App Service forwarding is enabled'


def check_agent_slots(ctx):
    configured = Context(ctx.template, ctx.environment,
                         {'agentHostname': 'agent.example.no', 'minimumAgentVersion': '0.3.1'})
    slots = app_settings(configured)
    if slots[0].get('Hosting__AgentHosts__0') != 'agent.example.no':
        raise Failed('production does not use the configured agent hostname')
    if any(slot.get('Agents__MinimumAgentVersion') != '0.3.1' for slot in slots):
        raise Failed('minimum agent version is not passed to every slot')
    for slot in app_settings(ctx):
        if slot.get('Hosting__AgentHosts__0') != 'disabled.invalid':
            raise Failed('P2 must be closed until an agent hostname is configured')
    if ctx.environment == 'prod':
        sticky = [r for r in ctx.of('Microsoft.Web/sites/config') if r.segments(1) == ('slotConfigNames',)]
        names = sticky[0].get('properties', 'appSettingNames') if len(sticky) == 1 else []
        for key in ('Agents__NonceKey', 'Agents__MinimumAgentVersion', 'Hosting__AgentHosts__0'):
            if key not in names:
                raise Failed(f'{key} does not stay with its slot')
        # reference() remains Unknown, so compare the evaluated portal/agent values by their resource references.
        if repr(slots[1].get('Hosting__AgentHosts__0')) != repr(slots[1].get('Hosting__PortalHosts__0')):
            raise Failed('staging must expose the agent smoke test on its own hostname')
    return 'P2 closed by default; explicit hostname and minimum version survive slot swaps'


def check_agent_smoke(scripts):
    deploy = scripts['deploy']
    if '/api/v1/agent/challenges' not in deploy or '"purpose":"enroll"' not in deploy:
        raise Failed('deployment does not smoke-test createAgentChallenge')
    if 'check_startup.py' not in deploy:
        raise Failed('deployment does not check local Production configuration before publishing')
    return 'deployment checks Production configuration and the stateless agent challenge'


def check_agent_alerts(ctx):
    configured = Context(ctx.template, ctx.environment, {'agentHostname': 'agent.example.no'})
    suffixes = ('agent-failures', 'agent-restarts', 'agent-memory', 'agent-rejected-batches', 'agent-intake')
    metrics_source = (ROOT / 'src/Sikkerheit.Host/Agents/AgentMetrics.cs').read_text()
    metric_names = set(re.findall(r'"(agent\.[\w.]+)"', metrics_source))
    for suffix in suffixes:
        found = [r for r in configured.of('Microsoft.Insights/scheduledQueryRules')
                 if known_end(r.name).endswith('-' + suffix)]
        if len(found) != 1 or found[0].get('properties', 'enabled') is not True:
            raise Failed(f'{suffix} must be enabled when the agent hostname is configured')
        criteria = found[0].get('properties', 'criteria', 'allOf')
        if not isinstance(criteria, list) or len(criteria) != 1:
            raise Failed(f'{suffix} has no alert criterion')
        query = criteria[0].get('query', '')
        unknown = set(re.findall(r'"(agent\.[\w.]+)"', query)) - metric_names
        if unknown:
            raise Failed(f'{suffix} refers to unpublished metrics: {sorted(unknown)}')
        if suffix == 'agent-intake' and not re.search(r'\bp95\s*>\s*2000\s+or\b', query):
            raise Failed('agent-intake must compare numeric requests.duration to 2000 milliseconds')
        if not found[0].get('properties', 'actions', 'actionGroups'):
            raise Failed(f'{suffix} has no notification action')
    return 'all five P2 alerts are configured and use metric names published by the service'


def check_job_alerts(ctx):
    sources = [(ROOT / path).read_text() for path in ('src/Sikkerheit.Host/Jobs/JobMetrics.cs',
                                                    'src/Sikkerheit.Host/M365/GraphMetrics.cs')]
    metrics = set(re.findall(r'"(sikkerheit\.[\w.]+)"', '\n'.join(sources)))
    for suffix in ('job-backlog', 'graph-throttling'):
        found = [r for r in ctx.of('Microsoft.Insights/scheduledQueryRules')
                 if known_end(r.name).endswith('-' + suffix)]
        if len(found) != 1 or found[0].get('properties', 'enabled') is not True:
            raise Failed(f'{suffix} must be enabled')
        query = found[0].get('properties', 'criteria', 'allOf')[0].get('query', '')
        names = set(re.findall(r'"(sikkerheit\.[\w.]+)"', query))
        if not names or names - metrics:
            raise Failed(f'{suffix} refers to missing or unpublished metrics')
        if not found[0].get('properties', 'actions', 'actionGroups'):
            raise Failed(f'{suffix} has no notification action')
    return 'backlog and Graph throttling alerts use published metrics and the notification action group'


CHECKS = (('runtime configuration', None, check_startup), ('agent slot settings', None, check_agent_slots),
          ('agent alerts', None, check_agent_alerts), ('job alerts', None, check_job_alerts))
SCRIPT_CHECKS = (('agent deployment smoke', None, check_agent_smoke),)

for key in ('Agents__NonceKey', 'M365__ClientId', 'DataProtection__BlobUri', 'Hosting__AgentHosts__0'):
    mutation('prod', 'runtime configuration', f'missing {key}')(
        lambda t, s, key=key: replace_text(t, key, 'Missing__Setting'))
mutation('test', 'runtime configuration', 'forwarded headers disabled')(
    lambda t, s: replace_text(t, '"ASPNETCORE_FORWARDEDHEADERS_ENABLED": "true"',
                            '"ASPNETCORE_FORWARDEDHEADERS_ENABLED": "false"'))
mutation('prod', 'runtime configuration', 'collection concurrency parameter ignored')(
    lambda t, s: replace_text(t, "[format('{0}', parameters('collectionConcurrency'))]", '8'))
mutation('test', 'runtime configuration', 'maintenance lane missing')(
    lambda t, s: replace_text(t, 'Jobs__MaintenanceConcurrency', 'Missing__MaintenanceConcurrency'))
mutation('prod', 'no secrets in settings', 'nonce key as a plain value')(
    lambda t, s: replace_text(t, '@Microsoft.KeyVault(VaultName={0};SecretName=agents-nonce-key)', 'plain-{0}'))


@mutation('prod', 'agent slot settings', 'minimum version not sticky')
def drop_sticky(template, scripts):
    count = 0
    for resource in raw_of(template, 'Microsoft.Web/sites/config'):
        properties = resource.get('properties', {})
        names = properties.get('appSettingNames', []) if isinstance(properties, dict) else []
        if 'Agents__MinimumAgentVersion' in names:
            names.remove('Agents__MinimumAgentVersion')
            count += 1
    return count


mutation('scripts', 'agent deployment smoke', 'agent challenge smoke missing')(
    lambda t, s: replace_script(s, 'deploy', '/api/v1/agent/challenges', '/api/v1/no-challenge'))
mutation('prod', 'agent alerts', 'memory alert refers to an unpublished metric')(
    lambda t, s: replace_text(t, 'agent.working_set_mb', 'agent.nonexistent'))
mutation('prod', 'agent alerts', 'numeric duration compared with a timespan')(
    lambda t, s: replace_text(t, 'p95 > 2000', 'p95 > 2s'))
mutation('test', 'agent alerts', 'duration threshold accidentally expressed in seconds')(
    lambda t, s: replace_text(t, 'p95 > 2000', 'p95 > 2'))
mutation('prod', 'job alerts', 'backlog alert refers to an unpublished metric')(
    lambda t, s: replace_text(t, 'sikkerheit.jobs.oldest_ready_age', 'sikkerheit.jobs.nonexistent'))


@mutation('test', 'agent alerts', 'agent alerts disabled after enabling the hostname')
def disable_agent_alerts(template, scripts):
    count = 0
    for resource in raw_of(template, 'Microsoft.Insights/scheduledQueryRules'):
        if resource.get('copy', {}).get('name') == 'alerts':
            resource['properties']['enabled'] = False
            count += 1
    return count
