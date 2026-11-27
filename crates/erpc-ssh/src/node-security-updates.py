# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0

def cached_security_candidates(packages, compare, time_left):
    """Count installed packages with a newer candidate from a trusted security pocket."""
    unknown = {"status": "unknown", "packages": None}
    count = 0
    saw_security_origin = False
    for package in packages:
        if not time_left():
            return unknown
        installed = package.installed
        if installed is None:
            continue
        candidate = package.candidate
        if candidate is None:
            continue
        for origin in candidate.origins:
            if origin.trusted and (
                (origin.origin == "Ubuntu" and origin.archive.endswith("-security"))
                or (origin.origin == "Debian" and origin.label == "Debian-Security")
            ):
                saw_security_origin = True
                if compare(candidate.version, installed.version) > 0:
                    count += 1
                    if count > 65535:
                        return unknown
                break
    if not saw_security_origin:
        return unknown
    return {"status": "available" if count else "none_in_cached_candidates", "packages": count}


def security_update_summary():
    # Work only with the node's existing APT view. A successful empty result
    # describes cached candidates, including the machine's pinning and holds.
    import time
    try:
        import apt
        import apt_pkg
        deadline = time.monotonic() + 8
        with apt.Cache(memonly=True) as cache:
            return cached_security_candidates(
                cache, apt_pkg.version_compare, lambda: time.monotonic() < deadline
            )
    except (ImportError, OSError, SystemError, RuntimeError, ValueError):
        return {"status": "unknown", "packages": None}
