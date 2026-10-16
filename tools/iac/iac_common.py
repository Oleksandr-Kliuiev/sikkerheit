"""Shared parts of the IaC checks (check_arm.py, restore_checks.py): the failure type, helpers for resources and shell
scripts, and the registry of deliberately broken copies for the self-test. Standard library only.
"""
import json
import re

from arm_eval import MISSING, known_end, raw_resources, show


class Failed(Exception):
    """A check failed; the message is its one-line reason."""


def one_or_more(ctx, kind, what):
    found = ctx.of(kind)
    if not found:
        raise Failed(f'no {what}')
    return found


def settings_of(resource):
    value = resource.get('properties')
    if not isinstance(value, dict):
        raise Failed(f'cannot evaluate the settings of {resource.describe()}: {show(value)}')
    return value


def identities_of(resource):
    """Names of the user-assigned identities of a resource, lower case."""
    assigned = resource.get('identity', 'userAssignedIdentities')
    if assigned is MISSING or assigned is None:
        return []
    if not isinstance(assigned, dict):
        raise Failed(f'cannot evaluate the identities of {resource.describe()}: {show(assigned)}')
    names = []
    for key in assigned:
        end = known_end(key).lower()
        if '/providers/microsoft.managedidentity/userassignedidentities/' not in end:
            raise Failed(f'cannot evaluate the identity {show(key)} of {resource.describe()}')
        names.append(end.rsplit('/', 1)[-1])
    return names


# --- Shell scripts -----------------------------------------------------------------------------------------------

def commands(script):
    """Shell commands without comment lines, continuation lines joined."""
    result, current = [], ''
    for line in script.splitlines():
        stripped = line.strip()
        if not current and stripped.startswith('#'):
            continue
        if stripped.endswith('\\'):
            current += stripped[:-1] + ' '
            continue
        result.append(current + stripped)
        current = ''
    return result + ([current] if current else [])


# An az command at the start of a command (also after «!», «{», «if», «then»...), not inside an echo text.
AZ = r'(?:^|[;&|(!{]\s*|\b(?:if|then|else|elif|do|while|until)\s+)az\s+'


# --- Self-test: deliberately broken copies must fail -------------------------------------------------------------

MUTATIONS = []


def mutation(label, title, description):
    def register(function):
        MUTATIONS.append((description, label, title, function))
        return function
    return register


def raw_of(template, kind):
    return [raw for full, raw in raw_resources(template) if full.lower() == kind.lower()]


def set_value(template, kind, path, value):
    for raw in raw_of(template, kind):
        target = raw
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    return len(raw_of(template, kind))


def replace_text(template, old, new):
    """Replaces text anywhere in the template, inside expressions too."""
    source = json.dumps(template)
    count = source.count(old)
    replaced = json.loads(source.replace(old, new))
    template.clear()
    template.update(replaced)
    return count


def replace_script(scripts, name, pattern, new):
    """Replaces a regular expression in one of the scripts; returns how many places changed."""
    scripts[name], count = re.subn(pattern, new, scripts[name])
    return count
