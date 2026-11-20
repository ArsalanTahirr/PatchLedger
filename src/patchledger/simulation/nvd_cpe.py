"""Conservative CPE 2.3 formatted-string matching.

Supports escaped literal punctuation and whole-field ANY (*).
Unsupported patterns return None, not a guessed match.
"""

from patchledger.simulation.nvd_versions import version_in_range

BOUND_KEYS = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)


def parse_cpe(value):
    if not isinstance(value, str):
        return None

    fields = []
    current = []
    escaped = False

    for char in value:
        if escaped:
            # Escaped wildcard characters need proper CPE
            # logical-value handling, not simple string matching.
            if char in "*?":
                return None

            current.append(char)
            escaped = False

        elif char == "\\":
            escaped = True

        elif char == ":":
            fields.append("".join(current))
            current = []

        else:
            current.append(char)

    if escaped:
        return None

    fields.append("".join(current))

    if len(fields) != 13 or fields[:2] != ["cpe", "2.3"]:
        return None

    attributes = fields[2:]

    if any(
        not part or "?" in part or ("*" in part and part != "*") for part in attributes
    ):
        return None

    return attributes


def match_cpe_criteria(installed_cpe, rule):
    if not isinstance(rule, dict):
        return None

    installed = parse_cpe(installed_cpe)
    criteria = parse_cpe(rule.get("criteria"))

    if installed is None or criteria is None:
        return None

    unknown = False

    for index, (actual, expected) in enumerate(zip(installed, criteria, strict=True)):
        # Version is handled separately.
        if index == 3:
            continue

        if actual == "*" and expected != "*":
            unknown = True
        elif expected != "*" and actual != expected:
            return False

    actual_version = installed[3]
    expected_version = criteria[3]

    if actual_version == "*":
        return None

    if expected_version != "*" and actual_version != expected_version:
        # NVD may use NA (-) while inventories report concrete versions.
        # Without a verified identity mapping, do not claim a negative.
        if expected_version == "-":
            return None
        return False

    if any(rule.get(key) is not None for key in BOUND_KEYS):
        if expected_version != "*":
            return None

        result = version_in_range(actual_version, rule)

        if result is None:
            return None

        if result is False:
            return False

    return None if unknown else True
