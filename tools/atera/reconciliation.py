"""Compare explicit links only. Names can suggest candidates but never establish an identity."""
from collections import Counter
from datetime import timedelta

from inventory_snapshots import timestamp, version


def reconcile(snapshot, now, minimum_version=None, stale_hours=48, snapshot_max_age_hours=24):
    minimum = version(minimum_version) if minimum_version else None

    def fresh(moment):
        return now - timedelta(hours=snapshot_max_age_hours) <= moment <= now + timedelta(minutes=5)

    atera_confirmed = snapshot['ateraComplete'] and fresh(snapshot['ateraCapturedAt'])
    sikkerheit_fresh = snapshot['sikkerheitComplete'] and fresh(snapshot['sikkerheitCapturedAt'])
    organizations = snapshot['organizations']
    customers = snapshot['customers']
    links = snapshot['deviceMappings']
    issues = []
    linked_devices = set()
    checked_agents = set()

    def add(kind, org, agent_id=None, device_id=None, label=None, **details):
        issues.append({'kind': kind, 'organizationId': org, 'agentId': agent_id, 'deviceId': device_id,
                       'displayName': label, **details})

    for agent_id, agent in sorted(snapshot['agents'].items()):
        org = customers.get(agent['customerId'])
        if org is None:
            continue  # Outside the explicitly configured pilot scope.
        checked_agents.add(agent_id)
        link = links.get(agent_id)
        organization = organizations.get(org)
        if link is None:
            candidates = [] if organization is None else [device['id'] for device in organization['devices'].values()
                if device['status'] == 'active' and agent['name'] and device['displayName'].casefold() == agent['name'].casefold()]
            add('unlinked_agent', org, agent_id, label=agent['name'], nameCandidates=candidates,
                candidateIdentityConfirmed=False)
            continue
        linked_devices.add((org, link['deviceId']))
        device = organization['devices'].get(link['deviceId']) if organization else None
        if device is None:
            confirmed = atera_confirmed and sikkerheit_fresh and organization is not None and organization['complete']
            add('mapped_device_missing' if confirmed else 'coverage_unconfirmed', org, agent_id, link['deviceId'], agent['name'])
            continue
        if device['status'] == 'revoked':
            add('revoked', org, agent_id, device['id'], device['displayName'])
            continue
        if device['identityState'] == 'identity_conflict':
            add('identity_conflict', org, agent_id, device['id'], device['displayName'])
        last_seen = timestamp(device['lastSeenAt'], 'lastSeenAt') if device.get('lastSeenAt') else None
        if last_seen and last_seen > now + timedelta(minutes=5):
            add('clock_inconsistent', org, agent_id, device['id'], device['displayName'])
        elif last_seen is None or last_seen < now - timedelta(hours=stale_hours):
            add('last_seen_old', org, agent_id, device['id'], device['displayName'], lastSeenAt=device.get('lastSeenAt'),
                rmmOnlinePresenceConfirmed=False)
        if minimum is not None and device.get('agentVersion') is None:
            add('version_unknown', org, agent_id, device['id'], device['displayName'])
        elif minimum is not None and version(device['agentVersion']) < minimum:
            add('version_below_minimum', org, agent_id, device['id'], device['displayName'], agentVersion=device['agentVersion'])

    for agent_id, link in sorted(links.items()):
        if agent_id not in snapshot['agents']:
            linked_devices.add((link['organizationId'], link['deviceId']))
            add('mapped_atera_agent_missing' if atera_confirmed else 'coverage_unconfirmed', link['organizationId'], agent_id, link['deviceId'])
    for org in sorted(set(customers.values())):
        organization = organizations.get(org)
        if organization is None or not organization['complete'] or not sikkerheit_fresh:
            add('organization_coverage_unconfirmed', org)
        if organization:
            for device in organization['devices'].values():
                if device['status'] == 'active' and (org, device['id']) not in linked_devices:
                    add('unlinked_device', org, device_id=device['id'], label=device['displayName'])
    coverage = bool(customers) and atera_confirmed and sikkerheit_fresh and all(
        org in organizations and organizations[org]['complete'] for org in customers.values())
    return {
        'schemaVersion': 1, 'asOf': now.isoformat(), 'comparisonComplete': coverage,
        'source': 'normalized_offline_snapshots', 'minimumAgentVersion': minimum_version,
        'snapshots': {'ateraCapturedAt': snapshot['ateraCapturedAt'].isoformat(),
                      'sikkerheitCapturedAt': snapshot['sikkerheitCapturedAt'].isoformat(),
                      'ateraCompleteAndFresh': atera_confirmed, 'sikkerheitCompleteAndFresh': sikkerheit_fresh},
        'scope': [{'customerId': customer, 'organizationId': org} for customer, org in sorted(customers.items())],
        'summary': {'scopedAteraAgents': len(checked_agents), 'outsideScopeAteraAgents': len(snapshot['agents']) - len(checked_agents),
                    'issuesByKind': dict(sorted(Counter(item['kind'] for item in issues).items()))},
        'issues': issues,
        'limitations': ['Names never establish device identity', 'No confirmed RMM online presence',
                        'No API calls, enrollment, revocation or ticket creation'],
    }
