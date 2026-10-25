"""Profile resolution. Exclude wins on one profile; a child may re-include a parent exclusion."""

from __future__ import annotations


RESOLUTION_RULES = (
    "A profile with neither include nor exclude selects every registered check.",
    "include is an allowlist and exclude is a denylist.",
    "When the same profile lists a check in both include and exclude, exclude wins.",
    "extends is resolved from the root profile to the child.",
    "A child include adds a check back after a parent excluded it.",
    "A child exclude is authoritative over both the parent selection and a child include.",
    "A child with neither include nor exclude keeps the parent selection.",
    "Unknown check IDs, missing profiles, and inheritance cycles are errors.",
)


def _present(profile, key):
    return key in profile and profile.get(key) is not None


def _check_ids(ids, registry, profile_name):
    if not isinstance(ids, list) or not all(isinstance(item, str) for item in ids):
        raise ValueError(f"profile {profile_name} include/exclude must be a list of check IDs")
    unknown = [item for item in ids if item not in registry]
    if unknown:
        raise ValueError(f"unknown check ID in profile {profile_name}: {', '.join(unknown)}")
    return set(ids)


def resolve_profile(name, conf, registry):
    """Return ``(selected_ids, trace)``.

    Precedence inside a profile: start from the inherited set, add include,
    then remove exclude. The root profile with neither filter selects every
    registered check.
    """
    if not isinstance(conf, dict):
        raise ValueError("configuration must be a mapping")
    profiles = conf.get("profiles")
    if not isinstance(profiles, dict):
        raise ValueError("configuration has no profiles mapping")
    if name not in profiles:
        raise ValueError(f"missing profile: {name}")

    chain = []
    seen = set()
    current = name
    while current:
        if current in seen:
            raise ValueError(f"inheritance cycle involving profile {current}")
        if current not in profiles:
            raise ValueError(f"missing profile: {current}")
        seen.add(current)
        chain.append(current)
        parent = profiles[current].get("extends")
        if parent is not None and not isinstance(parent, str):
            raise ValueError(f"profile {current} extends must be a profile name")
        current = parent
    chain.reverse()

    selected = None
    steps = []
    for profile_name in chain:
        profile = profiles[profile_name] or {}
        if not isinstance(profile, dict):
            raise ValueError(f"profile {profile_name} must be a mapping")
        has_include = _present(profile, "include")
        has_exclude = _present(profile, "exclude")
        included = _check_ids(profile.get("include") or [], registry, profile_name) if has_include else set()
        excluded = _check_ids(profile.get("exclude") or [], registry, profile_name) if has_exclude else set()
        if selected is None:
            if not has_include and not has_exclude:
                selected = set(registry)
                action = "select all registered checks"
            elif has_include:
                selected = set(included)
                action = "start from include allowlist"
            else:
                selected = set(registry) - excluded
                action = "start from all checks minus exclude"
            if has_include and has_exclude:
                selected = set(included) - excluded
                action = "include allowlist, then exclude (exclude wins)"
        else:
            action = "inherit parent selection"
            if has_include:
                selected |= included
                action = "re-include child allowlist on top of parent"
            if has_exclude:
                selected -= excluded
                action = "apply child exclude as the final removal"
        steps.append(
            {
                "profile": profile_name,
                "action": action,
                "include": sorted(included),
                "exclude": sorted(excluded),
                "selected": sorted(selected),
                "scope": profile.get("scope"),
                "baseline": profile.get("baseline"),
                "budgets": profile.get("budgets") or {},
            }
        )
    trace = {
        "profile": name,
        "chain": chain,
        "selected": sorted(selected),
        "steps": steps,
        "rules": list(RESOLUTION_RULES),
    }
    return selected, trace


def explain_profile(name, conf, registry):
    selected, trace = resolve_profile(name, conf, registry)
    lines = [f"Profile {name}", f"Inheritance: {' -> '.join(trace['chain'])}", "Rules:"]
    lines.extend(f"- {rule}" for rule in trace["rules"])
    for step in trace["steps"]:
        lines.append(
            f"- {step['profile']}: {step['action']}; include={step['include'] or '[]'}; exclude={step['exclude'] or '[]'}; scope={step.get('scope') or 'unspecified'}; budgets={step.get('budgets') or '{}'}"
        )
    lines.append(f"Selected checks ({len(selected)}): {', '.join(sorted(selected))}")
    return "\n".join(lines)


def merge_profiles(base, override):
    """User profile objects replace the same-named built-in profile. Others remain."""
    merged = {key: dict(value) if isinstance(value, dict) else value for key, value in (base or {}).items()}
    for key, value in (override or {}).items():
        merged[key] = value
    return merged
