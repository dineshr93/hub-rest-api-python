#!/usr/bin/env python

import argparse
import itertools
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

from blackduck.HubRestApi import HubInstance


BOM_ACCEPT = "application/vnd.blackducksoftware.bill-of-materials-6+json"
VULNERABILITY_DIGEST_ACCEPT = "application/vnd.blackducksoftware.vulnerability-digest-1+json"
SCAN_ACCEPT_HEADERS = [
    "application/vnd.blackducksoftware.scan-6+json",
    "application/vnd.blackducksoftware.scan-5+json",
    "application/vnd.blackducksoftware.scan-4+json",
]
DISPLAY_TIMEZONE = ZoneInfo("Europe/Paris") if ZoneInfo else None


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Read a project list file and print, for each project version, the "
            "unreviewed BOM components and security risks."
        )
    )
    parser.add_argument(
        "project_file",
        help=(
            "Text file with one project per line. The last whitespace-separated "
            "token is treated as the version and the rest of the line as the project name."
        ),
    )
    parser.add_argument(
        "--restconfig",
        default=".restconfig.json",
        help="Path to the Black Duck .restconfig.json file (default: .restconfig.json).",
    )
    return parser.parse_args()


def load_hub(restconfig_path):
    with open(restconfig_path, "r", encoding="utf-8") as config_file:
        config = json.load(config_file)

    baseurl = config.get("baseurl")
    insecure = config.get("insecure", False)
    debug = config.get("debug", False)

    if not baseurl:
        raise ValueError(f"Missing 'baseurl' in {restconfig_path}")

    api_token = config.get("api_token")
    if api_token:
        return HubInstance(
            baseurl,
            api_token=api_token,
            insecure=insecure,
            debug=debug,
            write_config_flag=False,
        )

    username = config.get("username")
    password = config.get("password")
    if username and password:
        return HubInstance(
            baseurl,
            username,
            password,
            insecure=insecure,
            debug=debug,
            write_config_flag=False,
        )

    raise ValueError(
        f"Expected either api_token or username/password in {restconfig_path}"
    )


def parse_project_file(project_file):
    project_versions = []
    with open(project_file, "r", encoding="utf-8") as input_file:
        for line_number, raw_line in enumerate(input_file, start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            parts = stripped.split()
            if len(parts) < 2:
                raise ValueError(
                    f"Invalid line {line_number} in {project_file}: {raw_line.rstrip()}"
                )

            version_name = parts[-1]
            project_name = " ".join(parts[:-1])
            project_versions.append((project_name, version_name))

    return project_versions


def with_paging(url, limit, offset):
    parsed = urlsplit(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.update({"limit": str(limit), "offset": str(offset)})
    return urlunsplit(parsed._replace(query=urlencode(query)))


def fetch_all_items(hub, url, accept_header, page_size=250):
    items = []
    offset = 0

    while True:
        response = hub.execute_get(
            with_paging(url, page_size, offset),
            custom_headers={"Accept": accept_header},
        )
        page_items = response.json().get("items", [])
        items.extend(page_items)

        if len(page_items) < page_size:
            return items

        offset += page_size


def get_version(hub, project_name, version_name):
    project = hub.get_project_by_name(project_name)
    if not project:
        raise LookupError(f"Project '{project_name}' was not found")

    version = hub.get_version_by_name(project, version_name)
    if not version:
        raise LookupError(
            f"Version '{version_name}' was not found in project '{project_name}'"
        )

    return version


def get_blackduck_project_version_link(version):
    version_href = version["_meta"]["href"]
    parsed = urlsplit(version_href)

    if parsed.path.startswith("/ui/"):
        return urlunsplit(parsed._replace(path=parsed.path.replace("/ui/", "/api/", 1)))

    return version_href+"/components"




def get_all_bom_components(hub, version):
    components_url = hub.get_link(version, "components")
    if not components_url:
        components_url = f"{version['_meta']['href']}/components"
    return fetch_all_items(hub, components_url, BOM_ACCEPT, page_size=1000)


def get_unreviewed_components(hub, version, components=None):
    if components is None:
        components = get_all_bom_components(hub, version)

    unreviewed = []
    for component in components:
        if component.get("reviewStatus") == "REVIEWED":
            continue

        unreviewed.append(
            (
                component.get("componentName", "<unknown component>"),
                component.get("componentVersionName", "<unknown version>"),
            )
        )

    return sorted(set(unreviewed), key=lambda item: (item[0].lower(), item[1].lower()))


# Order used both to pick a component's worst license risk severity and to
# classify that severity as high or low priority in reports/summaries.
LICENSE_RISK_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
LICENSE_RISK_HIGH_PRIORITY_LEVELS = {"CRITICAL", "HIGH"}


def get_component_license_risk_level(component):
    """Return a component's worst license risk severity, or None if it's OK/has no risk."""
    counts = component.get("licenseRiskProfile", {}).get("counts", [])
    present = {count.get("countType") for count in counts if count.get("count")}
    for level in LICENSE_RISK_SEVERITY_ORDER:
        if level in present:
            return level
    return None


def format_license_names(component):
    names = []
    for license_entry in component.get("licenses", []):
        name = license_entry.get("licenseDisplay")
        if name and name not in names:
            names.append(name)
    return ", ".join(names) if names else "Unknown License"


def get_license_risks(components):
    """Build (component_name, component_version, risk_level, license_names, ownership) rows
    for BOM components whose licenseRiskProfile reports a risk higher than OK.
    """
    risks = []
    for component in components:
        risk_level = get_component_license_risk_level(component)
        if not risk_level:
            continue

        licenses = component.get("licenses", [])
        ownership = licenses[0].get("ownership", "UNKNOWN") if licenses else "UNKNOWN"

        risks.append(
            (
                component.get("componentName", "<unknown component>"),
                component.get("componentVersionName", "<unknown version>"),
                risk_level,
                format_license_names(component),
                ownership,
            )
        )

    return sorted(set(risks), key=lambda item: (item[0].lower(), item[1].lower()))


def split_license_risks_by_priority(license_risks):
    """Split license risk rows into (high_priority, low_priority) by severity."""
    high_priority = [risk for risk in license_risks if risk[2] in LICENSE_RISK_HIGH_PRIORITY_LEVELS]
    low_priority = [risk for risk in license_risks if risk[2] not in LICENSE_RISK_HIGH_PRIORITY_LEVELS]
    return high_priority, low_priority


def _extract_related_id_from_vulnerability_record(vuln):
    """Pull the related vulnerability ID out of a GET /api/vulnerabilities/{id} record.

    Checks the top-level relatedVulnerability field first, then falls back to the
    _meta.links entry with rel "related-vulnerability" (the link BDSA records use to
    point at their mapped CVE).
    """
    if not isinstance(vuln, dict):
        return None

    related_vuln = str(vuln.get("relatedVulnerability") or "").strip()
    if related_vuln:
        return related_vuln.rstrip("/").split("/")[-1]

    for link in vuln.get("_meta", {}).get("links", []):
        if link.get("rel") == "related-vulnerability":
            href = str(link.get("href") or "").rstrip("/")
            if href:
                return href.split("/")[-1]

    return None


def fetch_related_vulnerability_id(hub, vulnerability_id, cache):
    """Look up the related CVE (or other) ID for a vulnerability (e.g. a BDSA).

    Fetches the vulnerability's own record from GET /api/vulnerabilities/{id} and follows
    its related-vulnerability link/field. Falls back to /vulnerabilities-digest (which also
    exposes a relatedVulnerabilityId) if the direct record doesn't have one.
    """
    if vulnerability_id in cache:
        return cache[vulnerability_id]

    related_id = None
    try:
        vuln = hub.get_vulnerabilities(vulnerability_id)
    except Exception:
        vuln = None
    related_id = _extract_related_id_from_vulnerability_record(vuln)

    if not related_id:
        url = hub.get_apibase() + "/vulnerabilities-digest" + hub._get_parameter_string(
            {"q": "vulnerabilityId:{}".format(vulnerability_id), "limit": 1}
        )
        try:
            response = hub.execute_get(url, custom_headers={"Accept": VULNERABILITY_DIGEST_ACCEPT})
            items = response.json().get("items", [])
        except Exception:
            items = []

        for digest_item in items:
            if digest_item.get("vulnerabilityId") == vulnerability_id:
                related_id = digest_item.get("relatedVulnerabilityId")
                break

    cache[vulnerability_id] = related_id
    return related_id


def format_vulnerability_ids(vulnerability, item=None, hub=None, digest_cache=None):
    """Format vulnerability ID(s) with links.
    
    Extracts CVE, USN IDs from various fields and formats with URLs.
    Returns a string like 'BDSA-2019-2021 [CVE-2013-0248: https://...] [USN-1234-56: https://...]'
    
    Args:
        vulnerability: The vulnerability object from API response
        item: Optional full item object to search for additional CVE/EUVD data
        hub: Optional HubInstance, used to fall back to /vulnerabilities-digest when
            no related CVE is present on the vulnerability record itself
        digest_cache: Optional dict used to cache /vulnerabilities-digest lookups across calls
    """
    vuln_id = (
        vulnerability.get("vulnerabilityName")
        or vulnerability.get("vulnerabilityId")
        or "<unknown vulnerability>"
    )
    
    # Collect all related IDs
    related_ids = []
    
    # Helper function to add unique IDs
    def add_if_unique(cve_id, id_type="CVE"):
        if not cve_id or not cve_id.startswith(id_type + "-"):
            return
        if any(cve_id in rid for rid in related_ids):
            return
        if id_type == "CVE":
            url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            related_ids.append(f"CVE: {cve_id} ({url})")
        elif id_type == "USN":
            url = f"https://security.ubuntu.com/usn/{cve_id}/"
            related_ids.append(f"USN: {cve_id} ({url})")
    
    # Check relatedVulnerability field (single reference like "/vulnerabilities/CVE-2013-0248")
    related_vuln = vulnerability.get("relatedVulnerability", "").strip()
    if related_vuln:
        parts = related_vuln.rstrip("/").split("/")
        if parts:
            related_id = parts[-1]
            if related_id and related_id != vuln_id:
                if related_id.startswith("CVE-"):
                    add_if_unique(related_id, "CVE")
                elif related_id.startswith("USN-"):
                    add_if_unique(related_id, "USN")
    
    # Check cves field (might be array of CVE objects or strings)
    for cves_source in [vulnerability, item or {}]:
        cves = cves_source.get("cves", [])
        if cves and isinstance(cves, list):
            for cve in cves:
                if isinstance(cve, dict):
                    cve_id = cve.get("name") or cve.get("id")
                else:
                    cve_id = str(cve).strip()
                add_if_unique(cve_id, "CVE")
    
    # Check usns field (might be array of USN objects or strings)
    for usns_source in [vulnerability, item or {}]:
        usns = usns_source.get("usns", [])
        if usns and isinstance(usns, list):
            for usn in usns:
                if isinstance(usn, dict):
                    usn_id = usn.get("name") or usn.get("id")
                else:
                    usn_id = str(usn).strip()
                add_if_unique(usn_id, "USN")
    
    # Check item-level vulnerability references (some APIs nest them differently)
    if item:
        # Check relatedVulnerabilities (plural)
        rel_vulns = item.get("relatedVulnerabilities", [])
        if isinstance(rel_vulns, list):
            for rel_vuln in rel_vulns:
                if isinstance(rel_vuln, dict):
                    rel_id = rel_vuln.get("name") or rel_vuln.get("id")
                elif isinstance(rel_vuln, str):
                    rel_id = rel_vuln.strip()
                else:
                    continue
                
                if rel_id.startswith("CVE-"):
                    add_if_unique(rel_id, "CVE")
                elif rel_id.startswith("USN-"):
                    add_if_unique(rel_id, "USN")

    # Fall back to the /vulnerabilities-digest endpoint for BDSA entries that don't
    # carry their related CVE on the BOM vulnerability record itself.
    if not related_ids and hub is not None and vuln_id.startswith("BDSA-"):
        cache = digest_cache if digest_cache is not None else {}
        related_id = fetch_related_vulnerability_id(hub, vuln_id, cache)
        if related_id:
            if related_id.startswith("CVE-"):
                add_if_unique(related_id, "CVE")
            elif related_id.startswith("USN-"):
                add_if_unique(related_id, "USN")

    if related_ids:
        return f"{vuln_id} [{', '.join(related_ids)}]"
    return vuln_id


def get_security_risks(hub, version):
    risks_url = hub.get_link(version, "vulnerable-components")
    if not risks_url:
        risks_url = f"{version['_meta']['href']}/vulnerable-bom-components"

    # Without this, unscored related CVEs (e.g. for some BDSAs) are omitted by the API.
    parsed_risks_url = urlsplit(risks_url)
    risks_query = dict(parse_qsl(parsed_risks_url.query, keep_blank_values=True))
    risks_query["showUnscoredRelatedVulnerability"] = "true"
    risks_url = urlunsplit(parsed_risks_url._replace(query=urlencode(risks_query)))

    vulnerable_components = fetch_all_items(hub, risks_url, BOM_ACCEPT, page_size=250)

    risks = []
    user_display_cache = {}
    vuln_digest_cache = {}
    for item in vulnerable_components:
        vulnerability_with_remediation = item.get("vulnerabilityWithRemediation", {})
        vulnerability = vulnerability_with_remediation or item.get("vulnerability", {})

        vulnerability_name = format_vulnerability_ids(
            vulnerability, item, hub=hub, digest_cache=vuln_digest_cache
        )
        cvss_score = vulnerability.get("overallScore")
        if cvss_score is None:
            cvss_score = vulnerability.get("baseScore")

        status_modifier_name = (
            vulnerability.get("remediationJustificationName")
            or vulnerability.get("securityStatusModifierName")
            or vulnerability.get("securityRiskStatusModifierName")
            or vulnerability.get("remediationJustification")
            or "UNKNOWN"
        )

        remediation_comment = (
            vulnerability.get("remediationComment")
            or vulnerability.get("comment")
            or item.get("comment")
            or ""
        )
        remediation_comment = str(remediation_comment).strip()

        remediation_actor = (
            vulnerability_with_remediation.get("remediationUpdatedBy")
            or vulnerability_with_remediation.get("remediationCreatedBy")
            or vulnerability.get("remediationUpdatedBy")
            or vulnerability.get("remediationCreatedBy")
            or "UNKNOWN"
        )
        remediation_actor = resolve_user_display_name(
            hub, remediation_actor, user_display_cache
        )

        remediation_updated_at = (
            vulnerability_with_remediation.get("remediationUpdatedAt")
            or vulnerability.get("remediationUpdatedAt")
            or ""
        )
        remediation_target_at = (
            vulnerability_with_remediation.get("remediationTargetAt")
            or vulnerability.get("remediationTargetAt")
            or ""
        )
        remediation_actual_at = (
            vulnerability_with_remediation.get("remediationActualAt")
            or vulnerability.get("remediationActualAt")
            or ""
        )

        risks.append(
            (
                item.get("componentName", "<unknown component>"),
                item.get("componentVersionName", "<unknown version>"),
                vulnerability_name,
                vulnerability.get("source", "UNKNOWN"),
                vulnerability.get("remediationStatus", "UNKNOWN"),
                cvss_score,
                status_modifier_name,
                remediation_comment,
                remediation_actor,
                remediation_updated_at,
                remediation_target_at,
                remediation_actual_at,
                vulnerability.get("relatedVulnerability", ""),
            )
        )

    return sorted(
        set(risks),
        key=lambda item: (
            item[0].lower(),
            item[1].lower(),
            item[2].lower(),
        ),
    )


def format_count_with_ignored(count, ignored_count, new_count=0):
    """Format a risk count, appending ignored/new counts in brackets if any.

    Example: format_count_with_ignored(7, 3, 2) -> "7 (ignored: 3, new: 2)"
    Example: format_count_with_ignored(7, 3, 0) -> "7 (ignored: 3)"
    Example: format_count_with_ignored(7, 0, 2) -> "7 (new: 2)"
    """
    details = []
    if ignored_count:
        details.append(f"ignored: {ignored_count}")
    if new_count:
        details.append(f"new: {new_count}")
    if details:
        return f"{count} ({', '.join(details)})"
    return str(count)


def format_cvss_score(score):
    if score is None:
        return "N/A"
    if isinstance(score, (int, float)):
        return f"{score:g}"
    return str(score)


def cvss_as_float(score):
    if score is None:
        return None
    if isinstance(score, (int, float)):
        return float(score)
    try:
        return float(str(score).strip())
    except (TypeError, ValueError):
        return None


def format_iso_date(value):
    if not value:
        return "No data"
    text = str(value).strip()
    if not text:
        return "No data"
    return text.split("T", 1)[0]


def format_iso_datetime(value):
    if not value:
        return "No data"

    text = str(value).strip()
    if not text:
        return "No data"

    dt = parse_scan_timestamp(text)
    if dt is None:
        return text

    if DISPLAY_TIMEZONE is not None:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
        dt = dt.astimezone(DISPLAY_TIMEZONE)

    if dt.tzinfo is None:
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    return dt.strftime("%Y-%m-%d %H:%M:%S %Z")


def format_age_hhmm(timestamp_value):
    scan_dt = parse_scan_timestamp(timestamp_value)
    if scan_dt is None:
        return "N/A"

    if scan_dt.tzinfo is None:
        scan_dt = scan_dt.replace(tzinfo=datetime.now().astimezone().tzinfo)

    elapsed_seconds = (datetime.now(scan_dt.tzinfo) - scan_dt).total_seconds()
    total_minutes = max(0, int(elapsed_seconds // 60))
    days = total_minutes // (24 * 60)
    hours = (total_minutes % (24 * 60)) // 60
    minutes = total_minutes % 60
    return f"{days}d {hours:02d}:{minutes:02d}"


def resolve_user_display_name(hub, username, cache):
    if not username:
        return "UNKNOWN"

    user_key = str(username).strip()
    if not user_key:
        return "UNKNOWN"

    if user_key == "UNKNOWN":
        return user_key

    if user_key in cache:
        return cache[user_key]

    try:
        response = hub.get_users(parameters={"q": f"userName:{user_key}", "limit": 1})
        users = response.get("items", [])
    except Exception:
        cache[user_key] = user_key
        return user_key

    if not users:
        cache[user_key] = user_key
        return user_key

    user = users[0]
    first_name = str(user.get("firstName") or "").strip()
    last_name = str(user.get("lastName") or "").strip()
    full_name = " ".join(part for part in (first_name, last_name) if part).strip()

    if full_name:
        cache[user_key] = full_name
        return full_name

    fallback = str(user.get("name") or user.get("userName") or user_key).strip()
    cache[user_key] = fallback or user_key
    return cache[user_key]


def parse_scan_timestamp(timestamp_value):
    if not timestamp_value:
        return None

    text = str(timestamp_value).strip()
    if not text:
        return None

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def execute_get_json_with_accept_fallback(hub, url, accept_headers):
    for accept_header in accept_headers:
        try:
            response = hub.execute_get(url, custom_headers={"Accept": accept_header})
            return response.json()
        except Exception:
            continue
    return None


def get_scan_actor(scan):
    created_by = scan.get("createdBy")
    if isinstance(created_by, dict):
        actor_text = str(created_by.get("userName") or created_by.get("name") or "").strip()
        if actor_text:
            return actor_text

    updated_by = scan.get("updatedBy")
    if isinstance(updated_by, dict):
        actor_text = str(updated_by.get("userName") or updated_by.get("name") or "").strip()
        if actor_text:
            return actor_text

    actor = (
        scan.get("createdByUserName")
        or scan.get("createdBy")
        or scan.get("updatedBy")
        or scan.get("scanOwner")
        or ""
    )
    actor_text = str(actor).strip()
    return actor_text or "UNKNOWN"


def resolve_user_from_reference(hub, user_reference):
    reference = str(user_reference or "").strip()
    if not reference:
        return "UNKNOWN"

    if not reference.startswith("http"):
        if reference.startswith("/api/"):
            reference = f"{hub.get_urlbase()}{reference}"
        elif reference.startswith("/"):
            reference = f"{hub.get_apibase()}{reference}"
        else:
            reference = f"{hub.get_apibase()}/{reference}"

    try:
        user_payload = hub.execute_get(reference).json()
    except Exception:
        return "UNKNOWN"

    first_name = str(user_payload.get("firstName") or "").strip()
    last_name = str(user_payload.get("lastName") or "").strip()
    full_name = " ".join(part for part in (first_name, last_name) if part).strip()
    if full_name:
        return full_name

    username = str(user_payload.get("userName") or user_payload.get("name") or "").strip()
    return username or "UNKNOWN"


def get_scan_timestamp(scan):
    for key in (
        "lastScanDate",
        "submittedAt",
        "scanUpdatedAt",
        "updatedAt",
        "createdAt",
        "scanCreatedAt",
        "finishedAt",
        "scanCompletedAt",
        "completionDate",
    ):
        value = scan.get(key)
        if value:
            return value
    return ""


def get_scanned_by_from_bom_events(hub, version_href):
    bom_events_url = f"{version_href}/bom-events"
    try:
        events = fetch_all_items(hub, bom_events_url, BOM_ACCEPT, page_size=250)
    except Exception:
        events = []

    if not events:
        return "UNKNOWN"

    latest_event = None
    latest_event_dt = None
    for event in events:
        submitted_at = event.get("submittedAt") or event.get("startTime")
        event_dt = parse_scan_timestamp(submitted_at)
        if latest_event is None:
            latest_event = event
            latest_event_dt = event_dt
            continue
        if event_dt and (latest_event_dt is None or event_dt > latest_event_dt):
            latest_event = event
            latest_event_dt = event_dt

    if not latest_event:
        return "UNKNOWN"

    submitted_by = latest_event.get("submittedBy", {})
    if isinstance(submitted_by, dict):
        first_name = str(submitted_by.get("firstName") or "").strip()
        last_name = str(submitted_by.get("lastName") or "").strip()
        full_name = " ".join(part for part in (first_name, last_name) if part).strip()
        if full_name:
            return full_name

        username = str(submitted_by.get("userName") or "").strip()
        if username:
            return username

        user_reference = submitted_by.get("user")
        resolved_user = resolve_user_from_reference(hub, user_reference)
        if resolved_user != "UNKNOWN":
            return resolved_user

    if isinstance(submitted_by, str):
        submitted_text = submitted_by.strip()
        if submitted_text:
            return submitted_text

    return "UNKNOWN"


def get_bom_total_count(components):
    """Get total number of BOM components."""
    return len(components)





def get_last_scan_info(hub, version):
    version_href = version["_meta"]["href"]
    scan_date = "No data"
    scan_age = "N/A"

    # API docs: /bom-status contains lastScanDate for the project version.
    bom_status_url = f"{version_href}/bom-status"
    bom_status = execute_get_json_with_accept_fallback(hub, bom_status_url, [BOM_ACCEPT])
    if bom_status:
        last_scan_timestamp = bom_status.get("lastScanDate")
        scan_date = format_iso_datetime(last_scan_timestamp)
        scan_age = format_age_hhmm(last_scan_timestamp)

    codelocations_url = hub.get_link(version, "codelocations")
    if not codelocations_url:
        return scan_date, scan_age

    codelocations = fetch_all_items(
        hub,
        codelocations_url,
        "application/vnd.blackducksoftware.code-location-4+json",
        page_size=250,
    )

    latest_scan = None
    latest_scan_dt = None

    for codelocation in codelocations:
        latest_scan_url = (
            hub.get_link(codelocation, "latest-scan")
            or f"{codelocation['_meta']['href']}/latest-scan-summary"
        )
        if not latest_scan_url:
            continue

        scan = execute_get_json_with_accept_fallback(
            hub, latest_scan_url, SCAN_ACCEPT_HEADERS
        )
        if not scan:
            continue

        timestamp_value = get_scan_timestamp(scan)
        scan_dt = parse_scan_timestamp(timestamp_value)

        if latest_scan is None:
            latest_scan = scan
            latest_scan_dt = scan_dt
            continue

        if scan_dt and (latest_scan_dt is None or scan_dt > latest_scan_dt):
            latest_scan = scan
            latest_scan_dt = scan_dt

    if not latest_scan:
        return scan_date, scan_age

    if scan_date == "No data":
        last_scan_timestamp = get_scan_timestamp(latest_scan)
        scan_date = format_iso_datetime(last_scan_timestamp)
        scan_age = format_age_hhmm(last_scan_timestamp)

    return scan_date, scan_age


# Row-number ranges (1-based, matching the "no" column) used to segregate the
# overall summary table into named groups of repos.
SUMMARY_GROUPS = [
    (1, 7, "CREATOR REPOS"),
    (8, 11, "CORE ANDROID APP REPOS"),
]

def get_summary_group_label(no):
    """Return the group label for a given "no" row number, or None if ungrouped."""
    for start, end, label in SUMMARY_GROUPS:
        if start <= no <= end:
            return label
    return None


def render_summary_table(project_summaries, title="OVERALL SUMMARY"):
    """Render a summary table for the given project summaries."""
    now = datetime.now(DISPLAY_TIMEZONE) if DISPLAY_TIMEZONE else datetime.now()
    state_as_of = now.strftime("%Y-%m-%d %H:%M:%S %Z").strip()

    lines = [
        "",
        "=" * 169,
        f"{title} [state as of: {state_as_of}]",
        "=" * 169,
        f"{'no':<5} | {'projects':<42} | {'last_scanned':<24} | {'unreview_components_count':<23} | {'security_cvss>7':<23} | {'security_cvss<7':<23} | {'misc':<10}",
        "-" * 169,
    ]

    # License risks are rendered in a separate table below since they were
    # crowding out the "misc" column in narrow terminals/console logs.
    license_lines = [
        "",
        f"{title} LICENSE RISKS",
        "-" * 169,
        f"{'no':<5} | {'projects':<42} | {'last_scanned':<24} | {'license_risk_high':<20} | {'license_risk_low':<20} | {'misc':<10}",
        "-" * 169,
    ]

    # Links are rendered in a separate table below since they are long enough
    # to push the "misc" column out of view in narrow terminals/console logs.
    link_lines = [
        "",
        f"{title} LINKS",
        "-" * 169,
        f"{'no':<5} | {'projects':<42} | {'link'}",
        "-" * 169,
    ]

    current_group = None
    for summary in project_summaries:
        no = summary['no']
        group_label = get_summary_group_label(no)
        if group_label is not None and group_label != current_group:
            lines.append(f"--- {group_label} ---")
            license_lines.append(f"--- {group_label} ---")
            link_lines.append(f"--- {group_label} ---")
            current_group = group_label

        projects = summary['projects']
        blackduck_link = summary.get('blackduck_link') or ""
        unreview_components_count = summary['unreview_components_count']
        security_cvss_gt_7 = summary['security_cvss>7']
        security_cvss_lt_7 = summary['security_cvss<7']
        license_risk_high = summary['license_risk_high']
        license_risk_low = summary['license_risk_low']
        last_scanned = summary['last_scanned']
        misc = summary['misc']
        
        # Truncate projects if too long
        if len(projects) > 42:
            projects = projects[:39] + "..."
        
        lines.append(f"{no:<5} | {projects:<42} | {last_scanned:<22} | {unreview_components_count:<23} | {security_cvss_gt_7:<23} | {security_cvss_lt_7:<23} | {misc:<10}")

        license_lines.append(f"{no:<5} | {projects:<42} | {last_scanned:<22} | {license_risk_high:<20} | {license_risk_low:<20} | {misc:<10}")

        # Append the plain link at the end of the line (not padded) so Jenkins'
        # console log auto-linkifies it. OSC-8 escape codes are avoided here
        # because Jenkins does not interpret them and shows them as garbage.
        link_lines.append(f"{no:<5} | {projects:<42} | {blackduck_link}")

    lines.append("=" * 169)
    license_lines.append("=" * 169)
    link_lines.append("=" * 169)
    return "\n".join(lines + license_lines + link_lines)


def format_risk_details(risk):
    """Build the '(source, cvss: ..., remediation: ..., ...)' details string for a risk row."""
    (
        _component_name,
        _component_version,
        _vulnerability_name,
        source,
        remediation_status,
        cvss_score,
        status_modifier_name,
        remediation_comment,
        remediation_actor,
        remediation_updated_at,
        remediation_target_at,
        remediation_actual_at,
        _related_vulnerability,
    ) = risk

    details_parts = [
        source,
        f"cvss: {format_cvss_score(cvss_score)}",
        f"remediation: {remediation_status}",
    ]

    if status_modifier_name and status_modifier_name != "UNKNOWN":
        details_parts.append(f"security status modifier: {status_modifier_name}")

    target_date = format_iso_date(remediation_target_at)
    if target_date != "No data":
        details_parts.append(f"target date: {target_date}")

    actual_date = format_iso_date(remediation_actual_at)
    if actual_date != "No data":
        details_parts.append(f"actual date: {actual_date}")

    updated_date = format_iso_date(remediation_updated_at)
    actor = str(remediation_actor or "").strip()
    if updated_date != "No data" and actor and actor != "UNKNOWN":
        details_parts.append(f"last updated: {updated_date} by {actor}")
    elif updated_date != "No data":
        details_parts.append(f"last updated: {updated_date}")
    elif actor and actor != "UNKNOWN":
        details_parts.append(f"last updated by: {actor}")

    details = ", ".join(details_parts)
    if remediation_comment:
        details = f"{details}, comment: {remediation_comment}"

    return details


def render_grouped_risks(risks):
    """Render risk rows grouped by (component name, component version), with both
    the components and the vulnerabilities under each component enumerated (1., 2., ...).

    Assumes risks are already sorted so that rows for the same component name and
    version are adjacent (this holds for the output of get_security_risks()).
    """
    lines = []
    for component_index, ((component_name, component_version), group) in enumerate(
        itertools.groupby(risks, key=lambda risk: (risk[0], risk[1])),
        start=1,
    ):
        lines.append(f"{component_index}. {component_name} {component_version}:")
        for vuln_index, risk in enumerate(group, start=1):
            vulnerability_name = risk[2]
            details = format_risk_details(risk)
            lines.append(f"    {vuln_index}. {vulnerability_name} ({details})")

    return lines


def render_grouped_license_risks(license_risks):
    """Render license risk rows, one line per component (1., 2., ...)."""
    lines = []
    for index, (component_name, component_version, risk_level, license_names, ownership) in enumerate(
        license_risks, start=1
    ):
        lines.append(
            f"{index}. {component_name} {component_version}: {risk_level} "
            f"(license: {license_names}, ownership: {ownership})"
        )
    return lines


def render_project_report(
    report_number,
    total_reports,
    project_name,
    version_name,
    scan_date,
    scan_age,
    blackduck_link,
    unreviewed_components,
    security_risks,
    license_risks=None,
    summary_data=None,
):
    license_risks = license_risks or []
    lines = [
        "=" * 169,
        (
            f"[{report_number}/{total_reports}] {project_name} {version_name} "
            f"(last scanned: {scan_date}, age: {scan_age}) "
            f"<{'-' * (100 - len(str(report_number)) - len(str(total_reports)))}[{report_number}/{total_reports}]"
        ),
    ]
    
    # Add project-specific summary at the top
    if summary_data:
        now = datetime.now(DISPLAY_TIMEZONE) if DISPLAY_TIMEZONE else datetime.now()
        state_as_of = now.strftime("%Y-%m-%d %H:%M:%S %Z").strip()

        lines.extend([
            f"PROJECT SUMMARY [state as of: {state_as_of}]",
            "-" * 169,
            f"{'no':<5} | {'projects':<42} | {'last_scanned':<23} | {'unreview_components_count':<23} | {'security_cvss>7':<23} | {'security_cvss<7':<23} | {'license_risk_high':<20} | {'license_risk_low':<20} | {'misc':<10} |",
            "-" * 169,
        ])
        
        no = summary_data['no']
        projects = summary_data['projects']
        unreview_components_count = summary_data['unreview_components_count']
        security_cvss_gt_7 = summary_data['security_cvss>7']
        security_cvss_lt_7 = summary_data['security_cvss<7']
        license_risk_high = summary_data['license_risk_high']
        license_risk_low = summary_data['license_risk_low']
        last_scanned = summary_data['last_scanned']
        misc = summary_data['misc']
        
        # Truncate projects if too long
        if len(projects) > 42:
            projects = projects[:39] + "..."
        
        # Plain link at end of line (not padded) so Jenkins' console log
        # auto-linkifies it; OSC-8 escapes are not used since Jenkins doesn't
        # interpret them.
        lines.append(f"{no:<5} | {projects:<42} | {last_scanned:<22} | {unreview_components_count:<23} | {security_cvss_gt_7:<23} | {security_cvss_lt_7:<23} | {license_risk_high:<20} | {license_risk_low:<20} | {misc:<10} |")
        lines.append("-" * 169)
    
    lines.extend([
        f"Black Duck link: {blackduck_link}",
        "",
        "Unreviewed components:",
    ])

    if unreviewed_components:
        lines.extend(f"- {name} {version}" for name, version in unreviewed_components)
    else:
        lines.append("- None")

    lines.extend([
        "",
        "~" * 80,
        "SECURITY ISSUES (includes ignored issues)",
        "~" * 80,
    ])

    high_priority_risks = []
    low_priority_risks = []
    for risk in security_risks:
        cvss_value = cvss_as_float(risk[5])
        if cvss_value is not None and cvss_value >= 7:
            high_priority_risks.append(risk)
        else:
            low_priority_risks.append(risk)

    lines.append("Security issues (cvss >= 7):")
    if high_priority_risks:
        lines.append("-" * 80)
        lines.extend(render_grouped_risks(high_priority_risks))
    else:
        lines.append("- None")

    lines.append("")
    lines.append("low priority  issues(cvss < 7):")
    if low_priority_risks:
        lines.append("-" * 80)
        lines.extend(render_grouped_risks(low_priority_risks))
    else:
        lines.append("- None")

    lines.extend([
        "",
        "~" * 80,
        "LICENSE ISSUES",
        "~" * 80,
    ])

    license_high_priority, license_low_priority = split_license_risks_by_priority(license_risks)

    lines.append("License issues (critical/high):")
    if license_high_priority:
        lines.append("-" * 80)
        lines.extend(render_grouped_license_risks(license_high_priority))
    else:
        lines.append("- None")

    lines.append("")
    lines.append("License issues (medium/low/unknown):")
    if license_low_priority:
        lines.append("-" * 80)
        lines.extend(render_grouped_license_risks(license_low_priority))
    else:
        lines.append("- None")

    return "\n".join(lines)


def main():
    args = parse_args()
    project_file = Path(args.project_file)
    restconfig_path = Path(args.restconfig)

    hub = load_hub(restconfig_path)
    reports = []
    project_summaries = []
    project_versions = parse_project_file(project_file)
    total_reports = len(project_versions)

    for report_number, (project_name, version_name) in enumerate(project_versions, start=1):
        try:
            version = get_version(hub, project_name, version_name)
            scan_date, scan_age = get_last_scan_info(hub, version)
            blackduck_link = get_blackduck_project_version_link(version)
            all_components = get_all_bom_components(hub, version)
            unreviewed_components = get_unreviewed_components(hub, version, all_components)
            security_risks = get_security_risks(hub, version)
            license_risks = get_license_risks(all_components)
            total_bom = get_bom_total_count(all_components)
            
            unreview_components_count = len(unreviewed_components)
            
            high_priority_risks_count = 0
            low_priority_risks_count = 0
            high_priority_ignored_count = 0
            low_priority_ignored_count = 0
            high_priority_new_count = 0
            low_priority_new_count = 0
            for risk in security_risks:
                cvss_value = cvss_as_float(risk[5])
                risk_status = str(risk[4] or "").strip().upper()
                is_ignored = risk_status == "IGNORED"
                is_new = risk_status == "NEW"
                if cvss_value is not None and cvss_value >= 7:
                    high_priority_risks_count += 1
                    if is_ignored:
                        high_priority_ignored_count += 1
                    if is_new:
                        high_priority_new_count += 1
                else:
                    low_priority_risks_count += 1
                    if is_ignored:
                        low_priority_ignored_count += 1
                    if is_new:
                        low_priority_new_count += 1

            security_cvss_gt_7 = format_count_with_ignored(
                high_priority_risks_count, high_priority_ignored_count, high_priority_new_count
            )
            security_cvss_lt_7 = format_count_with_ignored(
                low_priority_risks_count, low_priority_ignored_count, low_priority_new_count
            )

            license_risks_high, license_risks_low = split_license_risks_by_priority(license_risks)
            license_risk_high_count = len(license_risks_high)
            license_risk_low_count = len(license_risks_low)

            project_summaries.append({
                'no': report_number,
                'projects': f"{project_name} {version_name}",
                'blackduck_link': blackduck_link,
                'last_scanned': scan_date,
                'unreview_components_count': unreview_components_count,
                'security_cvss>7': security_cvss_gt_7,
                'security_cvss<7': security_cvss_lt_7,
                'license_risk_high': license_risk_high_count,
                'license_risk_low': license_risk_low_count,
                'misc': f"BOM:{total_bom}",
            })
            
            # Create summary for this project to pass to render function
            project_summary = {
                'no': report_number,
                'projects': f"{project_name} {version_name}",
                'blackduck_link': blackduck_link,
                'last_scanned': scan_date,
                'unreview_components_count': unreview_components_count,
                'security_cvss>7': security_cvss_gt_7,
                'security_cvss<7': security_cvss_lt_7,
                'license_risk_high': license_risk_high_count,
                'license_risk_low': license_risk_low_count,
                'misc': f"BOM:{total_bom}",
            }
            
            reports.append(
                render_project_report(
                    report_number,
                    total_reports,
                    project_name,
                    version_name,
                    scan_date,
                    scan_age,
                    blackduck_link,
                    unreviewed_components,
                    security_risks,
                    license_risks=license_risks,
                    summary_data=project_summary,
                )
            )
        except LookupError as error:
            reports.append(
                "\n".join(
                    [
                        "=" * 80,
                        f"[{report_number}/{total_reports}] {project_name} {version_name}",
                        "-" * 80,
                        f"Error: {error}",
                    ]
                )
            )
            project_summaries.append({
                'no': report_number,
                'projects': f"{project_name} {version_name}",
                'blackduck_link': None,
                'last_scanned': 'No data',
                'unreview_components_count': 0,
                'security_cvss>7': 0,
                'security_cvss<7': 0,
                'license_risk_high': 0,
                'license_risk_low': 0,
                'misc': 'N/A',
            })

    # Print overall summary at the start
    print(render_summary_table(project_summaries, "OVERALL SUMMARY"))
    print("\n\n".join(reports))
    
    # Print overall summary at the end
    print(render_summary_table(project_summaries, "OVERALL SUMMARY"))
    print()


if __name__ == "__main__":
    main()
