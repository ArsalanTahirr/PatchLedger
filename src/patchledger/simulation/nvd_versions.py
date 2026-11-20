"""Conservative version comparison for numeric dotted versions."""

import re

NUMERIC_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")


def compare_versions(installed: str, boundary: str):
    """Return -1, 0, 1, or None when comparison is unsupported."""
    if not (
        NUMERIC_VERSION.fullmatch(installed) and NUMERIC_VERSION.fullmatch(boundary)
    ):
        return None

    left = [int(x) for x in installed.split(".")]
    right = [int(x) for x in boundary.split(".")]

    length = max(len(left), len(right))
    left += [0] * (length - len(left))
    right += [0] * (length - len(right))

    return (left > right) - (left < right)


def version_in_range(installed: str, rule: dict):
    """
    Return True, False, or None.

    None means that the version comparison is inconclusive.
    """
    bounds = (
        ("versionStartIncluding", False, True),
        ("versionStartExcluding", False, False),
        ("versionEndIncluding", True, True),
        ("versionEndExcluding", True, False),
    )

    for field, is_end, inclusive in bounds:
        boundary = rule.get(field)
        if boundary is None:
            continue

        result = compare_versions(installed, boundary)

        if result is None:
            return None

        if is_end:
            if result > 0 or (result == 0 and not inclusive):
                return False
        else:
            if result < 0 or (result == 0 and not inclusive):
                return False

    return True
