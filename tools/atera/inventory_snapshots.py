"""Validate normalized offline snapshots; this format is not an assumed Atera API response schema."""
from datetime import datetime, timezone
import re
from uuid import UUID
import unicodedata


class InvalidSnapshot(ValueError):
    pass


def object_value(value, label):
    if not isinstance(value, dict):
        raise InvalidSnapshot(f'{label} must be an object')
    return value


def array_value(value, label):
    if not isinstance(value, list) or len(value) > 100000:
        raise InvalidSnapshot(f'{label} must be an array of at most 100000 entries')
    return value


def identifier(value, label):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise InvalidSnapshot(f'{label} must be a positive integer')
    return value


def guid(value, label):
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError) as error:
        raise InvalidSnapshot(f'{label} must be a UUID') from error


def timestamp(value, label):
    try:
        moment = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if moment.tzinfo is None:
            raise ValueError('timezone required')
        return moment.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError) as error:
        raise InvalidSnapshot(f'{label} must be an ISO timestamp with a timezone') from error


def version(value):
    if not isinstance(value, str) or len(value) > 32 or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value):
        raise InvalidSnapshot('agentVersion must be x.y.z')
    return tuple(int(part) for part in value.split('.'))


def name(value):
    if not isinstance(value, str) or len(value) > 120 or any(unicodedata.category(char) in ('Cc', 'Cf', 'Cs') for char in value):
        raise InvalidSnapshot('device name must be text of at most 120 characters without control characters')
    return value


def complete(value, label):
    if not isinstance(value, bool):
        raise InvalidSnapshot(f'{label} must explicitly be true or false')
    return value


def read_snapshot(document):
    document = object_value(document, 'snapshot')
    if type(document.get('schemaVersion')) is not int or document['schemaVersion'] != 1:
        raise InvalidSnapshot('schemaVersion must be 1')
    atera = object_value(document.get('atera'), 'atera')
    sikkerheit = object_value(document.get('sikkerheit'), 'sikkerheit')
    result = {
        'ateraCapturedAt': timestamp(atera.get('capturedAt'), 'atera.capturedAt'),
        'sikkerheitCapturedAt': timestamp(sikkerheit.get('capturedAt'), 'sikkerheit.capturedAt'),
        'ateraComplete': complete(atera.get('complete'), 'atera.complete'),
        'sikkerheitComplete': complete(sikkerheit.get('complete'), 'sikkerheit.complete'),
        'agents': {}, 'organizations': {}, 'customers': {}, 'deviceMappings': {},
    }
    for raw in array_value(atera.get('agents'), 'atera.agents'):
        item = object_value(raw, 'Atera agent')
        agent_id = identifier(item.get('agentId'), 'agentId')
        if agent_id in result['agents']:
            raise InvalidSnapshot('duplicate Atera agentId')
        result['agents'][agent_id] = {
            'agentId': agent_id, 'customerId': identifier(item.get('customerId'), 'customerId'), 'name': name(item.get('name', '')),
        }
    for raw in array_value(sikkerheit.get('organizations'), 'sikkerheit.organizations'):
        item = object_value(raw, 'organization snapshot')
        org = guid(item.get('organizationId'), 'organizationId')
        if org in result['organizations']:
            raise InvalidSnapshot('duplicate organization snapshot')
        devices = {}
        pages = array_value(item.get('pages'), 'organization.pages')
        cursor = None
        seen_cursors = set()
        for index, raw_page in enumerate(pages):
            page = object_value(raw_page, 'device page')
            if 'cursor' not in page or page['cursor'] != cursor or (index > 0 and cursor is None):
                raise InvalidSnapshot('device pages must start at cursor null and follow the complete cursor chain')
            for raw_device in array_value(page.get('items'), 'device page.items'):
                device = dict(object_value(raw_device, 'device'))
                device['id'] = guid(device.get('id'), 'device.id')
                if device['id'] in devices:
                    raise InvalidSnapshot('duplicate device in organization pages')
                device['displayName'] = name(device.get('displayName', ''))
                if device.get('status') not in ('active', 'revoked'):
                    raise InvalidSnapshot('device.status must be active or revoked')
                if device.get('identityState') not in ('ok', 'identity_conflict'):
                    raise InvalidSnapshot('device.identityState must be ok or identity_conflict')
                if device.get('lastSeenAt') is not None:
                    timestamp(device['lastSeenAt'], 'device.lastSeenAt')
                if device.get('agentVersion') is not None:
                    version(device['agentVersion'])
                devices[device['id']] = device
            if 'nextCursor' not in page or (page['nextCursor'] is not None and not isinstance(page['nextCursor'], str)):
                raise InvalidSnapshot('device page.nextCursor must be null or a cursor')
            cursor = page['nextCursor']
            if cursor is not None:
                if not cursor or cursor in seen_cursors:
                    raise InvalidSnapshot('device pagination contains an empty or repeated cursor')
                seen_cursors.add(cursor)
        result['organizations'][org] = {'devices': devices, 'complete': bool(pages) and cursor is None}
    mapped_orgs = set()
    for raw in array_value(document.get('customerMappings'), 'customerMappings'):
        item = object_value(raw, 'customer mapping')
        customer = identifier(item.get('customerId'), 'customer mapping.customerId')
        org = guid(item.get('organizationId'), 'customer mapping.organizationId')
        if customer in result['customers'] or org in mapped_orgs:
            raise InvalidSnapshot('customer mappings must be one-to-one')
        result['customers'][customer] = org
        mapped_orgs.add(org)
    mapped_devices = set()
    for raw in array_value(document.get('deviceMappings'), 'deviceMappings'):
        item = object_value(raw, 'device mapping')
        agent_id = identifier(item.get('agentId'), 'device mapping.agentId')
        org = guid(item.get('organizationId'), 'device mapping.organizationId')
        device_id = guid(item.get('deviceId'), 'device mapping.deviceId')
        agent = result['agents'].get(agent_id)
        if org not in mapped_orgs or (agent is not None and result['customers'].get(agent['customerId']) != org):
            raise InvalidSnapshot('device mapping crosses customer/organization boundaries')
        if agent_id in result['deviceMappings'] or (org, device_id) in mapped_devices:
            raise InvalidSnapshot('device mappings must be one-to-one')
        result['deviceMappings'][agent_id] = {'organizationId': org, 'deviceId': device_id}
        mapped_devices.add((org, device_id))
    return result
