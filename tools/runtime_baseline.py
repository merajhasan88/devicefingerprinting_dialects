"""Runtime baselines from the release pipeline (DESIGN.md 84.6).

Run each release build on your reference phones and emulators -- every OS
level and ABI you support, cold start, a long session, every major feature --
so they send clean, complete scans. Then derive the build's memory profile from
those scans and publish it:

    DEVICE_TRUST_REPORTS_TOKEN=... python3 tools/runtime_baseline.py \\
        --base-url https://trust.example.com --installation <id> [--installation <id> ...] \\
        [--since 2026-10-16T09:00:00Z] [--release-label "2.4.1 (241)"] [--anon-margin 2]
    DEVICE_TRUST_BASELINES_TOKEN=... ... --publish

It reads the reference installations' scans through the business report feed
(a token with the reports role), keeps only the clean ones -- complete
evidence, verdict trusted: a scan with findings is no baseline -- and groups
them by app build, OS level and process ABI. Each group's profile is the most
writable-executable memory seen, the allocation size all of it divides into,
and the most unlabelled executable regions seen plus --anon-margin. It prints
the profiles; with --publish it posts each to /v1/business/runtime-baselines (a
token with the baselines role), which replaces the active profile of that
build, level and ABI. Never derive a baseline from the field: the first client
-- or a learned population -- must not set what clean looks like (review R5).
Standard library only.
"""
import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from functools import reduce
from math import gcd

PAGE_SIZE = 4096


def _call(base_url, token, method, path, body=None):
    request = urllib.request.Request(
        base_url.rstrip("/") + path, method=method,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_reports(base_url, token, installation_id, since=None):
    """Every report of one installation, oldest first, through the feed."""
    reports, query = [], {"installation_id": installation_id, "limit": "200"}
    if since:
        query["since"] = since
    while True:
        page = _call(base_url, token, "GET",
                     "/v1/business/integrity-reports?" + urllib.parse.urlencode(query))
        reports.extend(page.get("reports") or [])
        cursor = page.get("next_cursor")
        if not page.get("reports") or not cursor or cursor == query.get("cursor"):
            return reports
        query = {"installation_id": installation_id, "limit": "200", "cursor": cursor}


def _sizes(exec_maps):
    """The writable-executable allocation sizes one scan lists."""
    sizes = []
    for part in str(exec_maps.get("wx_size_classes") or "").split(","):
        size, _, count = part.strip().partition(":")
        if size.isdigit() and count.isdigit() and int(count) > 0:
            sizes.append(int(size))
    return sizes


def derive_profiles(reports, release_label=None, anon_margin=0):
    """(profiles, skipped): one profile per (platform, build, OS level, ABI)
    from clean, complete scans; the scans left out, with why."""
    groups, skipped = {}, []
    for report in reports:
        probes = report.get("probe_results") or {}
        if report.get("evidence_quality") != "complete" or report.get("verdict") != "trusted":
            skipped.append((report.get("report_id"), "%s, %s" % (
                report.get("evidence_quality"), report.get("verdict"))))
            continue
        platform = report.get("platform")
        ident, device = probes.get("app_identity") or {}, probes.get("device") or {}
        build = str(ident.get("apk_sha256" if platform == "android" else "executable_sha256")
                    or "").lower()
        if len(build) != 64:
            skipped.append((report.get("report_id"), "no build hash"))
            continue
        if platform == "android":
            level = device.get("sdk_int")
        else:
            major = str(device.get("os_version") or "").split(".")[0]
            level = int(major) if major.isdigit() else None
        level = level if isinstance(level, int) and not isinstance(level, bool) else None
        abi = device.get("abi") or None
        groups.setdefault((platform, build, level, abi), []).append(probes)
    profiles = []
    for (platform, build, level, abi), scans in sorted(groups.items(), key=str):
        exec_maps = [scan.get("exec_mappings") or {} for scan in scans]
        wx = [m.get("wx_bytes") for m in exec_maps if isinstance(m.get("wx_bytes"), int)]
        sizes = [size for m in exec_maps for size in _sizes(m)]
        anon = [m.get("anon_exec_unlabeled") for m in exec_maps
                if isinstance(m.get("anon_exec_unlabeled"), int)]
        profile = {"platform": platform, "app_build": build, "os_level": level, "abi": abi,
                   "release_label": release_label, "scans": len(scans)}
        if wx:
            profile["wx_bytes_max"] = max(wx)
            profile["wx_granularity"] = max(PAGE_SIZE, reduce(gcd, sizes)) if sizes else PAGE_SIZE
        if anon:
            profile["anon_exec_max"] = max(anon) + max(0, anon_margin)
        if "wx_bytes_max" in profile or "anon_exec_max" in profile:
            profiles.append(profile)
    return profiles, skipped


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--installation", action="append", required=True)
    parser.add_argument("--since")
    parser.add_argument("--release-label")
    parser.add_argument("--anon-margin", type=int, default=2)
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    reports_token = os.environ.get("DEVICE_TRUST_REPORTS_TOKEN", "")
    if not reports_token:
        raise SystemExit("set DEVICE_TRUST_REPORTS_TOKEN to a business token with the reports role")
    reports = [report for installation in args.installation
               for report in fetch_reports(args.base_url, reports_token, installation, args.since)]
    profiles, skipped = derive_profiles(reports, args.release_label, args.anon_margin)
    for report_id, why in skipped:
        print("left out %s: %s" % (report_id, why), file=sys.stderr)
    print(json.dumps(profiles, indent=2))
    if not args.publish:
        return 0
    baselines_token = os.environ.get("DEVICE_TRUST_BASELINES_TOKEN", "")
    if not baselines_token:
        raise SystemExit("set DEVICE_TRUST_BASELINES_TOKEN to a token with the baselines role")
    for profile in profiles:
        body = {key: value for key, value in profile.items() if key != "scans"}
        published = _call(args.base_url, baselines_token, "POST", "/v1/business/runtime-baselines",
                          body)
        print("published %s" % published["baseline"]["baseline_id"], file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
