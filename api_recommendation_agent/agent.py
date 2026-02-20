"""
Core API Recommendation Agent — Cybersecurity Edition.

Takes parsed API endpoints from security vendor documentation,
classifies them into SOC/IR capability categories, and produces
actionable recommendations for platform integration.

Uses rule-based classification offline, and optionally the
Anthropic Claude API for deeper integration planning.
"""

import json
from .parser import APIDocParser

# ---------------------------------------------------------------------------
# Cybersecurity capability classification rules
# ---------------------------------------------------------------------------

CAPABILITY_RULES = {
    # --- Investigation & Threat Hunting ---
    "threat_hunting": {
        "methods": ["GET", "POST"],
        "path_hints": [
            "hunt", "investigate", "threat", "search", "query", "event",
            "telemetry", "activity", "log", "audit", "trace", "forensic",
            "timeline", "process", "network", "dns", "connection",
        ],
        "description": "Search events, telemetry, and logs for threat hunting and investigation",
        "soc_priority": 1,
    },
    "detection_retrieval": {
        "methods": ["GET"],
        "path_hints": [
            "detection", "alert", "incident", "finding", "alarm",
            "notification", "trigger", "rule", "signature", "match",
        ],
        "description": "Retrieve detections, alerts, and incidents from security products",
        "soc_priority": 1,
    },
    # --- Alert & Incident Management ---
    "alert_creation": {
        "methods": ["POST", "PUT"],
        "path_hints": [
            "alert", "detection", "incident", "finding", "create",
            "notification", "alarm", "trigger", "case",
        ],
        "description": "Create or push alerts and incidents into security products",
        "soc_priority": 2,
    },
    "case_management": {
        "methods": ["GET", "POST", "PUT", "PATCH"],
        "path_hints": [
            "case", "incident", "ticket", "investigation", "workflow",
            "assign", "status", "priority", "escalat", "close", "resolve",
        ],
        "description": "Manage cases, incidents, and investigation workflows",
        "soc_priority": 2,
    },
    # --- Threat Intelligence ---
    "intel_management": {
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "path_hints": [
            "intel", "ioc", "indicator", "threat", "feed", "stix", "taxii",
            "hash", "domain", "ip", "url", "blocklist", "allowlist",
            "watchlist", "reputation", "enrichment", "observable",
        ],
        "description": "Push/pull IOC lists and threat intel feeds for detection and blocking",
        "soc_priority": 1,
    },
    # --- Response & Containment Actions ---
    "response_actions": {
        "methods": ["POST", "PUT"],
        "path_hints": [
            "isolat", "contain", "quarantine", "block", "kill", "remediat",
            "response", "action", "disable", "suspend", "lockout", "revoke",
            "terminate", "restrict", "playbook", "automat",
        ],
        "description": "Execute response actions: isolate host, block IP, quarantine file, kill process",
        "soc_priority": 1,
    },
    # --- Asset & Host Management ---
    "asset_management": {
        "methods": ["GET", "POST", "PUT"],
        "path_hints": [
            "host", "device", "endpoint", "asset", "agent", "sensor",
            "machine", "workstation", "server", "inventory", "cmdb",
            "hardware", "software", "installed",
        ],
        "description": "Query host/device inventory, agent status, and asset details",
        "soc_priority": 3,
    },
    # --- Identity & User Investigation ---
    "identity_investigation": {
        "methods": ["GET", "POST"],
        "path_hints": [
            "user", "identity", "account", "login", "session", "privilege",
            "access", "directory", "ldap", "azure_ad", "entra", "okta",
            "authentication", "mfa", "credential", "role",
        ],
        "description": "Investigate user identities, sessions, access patterns, and authentication events",
        "soc_priority": 2,
    },
    # --- Vulnerability Management ---
    "vulnerability_management": {
        "methods": ["GET", "POST"],
        "path_hints": [
            "vuln", "cve", "exploit", "patch", "scan", "assess",
            "weakness", "compliance", "baseline", "remediat", "risk_score",
        ],
        "description": "Query vulnerabilities, CVEs, scan results, and compliance posture",
        "soc_priority": 3,
    },
    # --- Policy & Configuration ---
    "policy_management": {
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE"],
        "path_hints": [
            "policy", "rule", "config", "setting", "exclusion", "exception",
            "whitelist", "suppress", "tuning", "prevention", "protection",
            "group", "profile",
        ],
        "description": "Manage detection rules, prevention policies, exclusions, and product configuration",
        "soc_priority": 4,
    },
    # --- SIEM & Log Ingestion ---
    "log_ingestion": {
        "methods": ["POST", "PUT"],
        "path_hints": [
            "ingest", "log", "syslog", "event", "collector", "source",
            "forward", "stream", "pipeline", "parser", "index",
        ],
        "description": "Push logs and events into SIEM or log management platforms",
        "soc_priority": 3,
    },
    # --- Webhooks & Notifications ---
    "webhook_notification": {
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "path_hints": [
            "webhook", "hook", "callback", "subscribe", "notification",
            "stream", "realtime", "push",
        ],
        "description": "Subscribe to real-time alerts and event streams via webhooks",
        "soc_priority": 2,
    },
    # --- Reporting & Analytics ---
    "reporting": {
        "methods": ["GET", "POST"],
        "path_hints": [
            "report", "analytics", "dashboard", "summary", "metric",
            "stat", "trend", "aggregate", "executive", "posture",
        ],
        "description": "Generate security reports, dashboards, and posture analytics",
        "soc_priority": 4,
    },
    # --- Authentication to the Vendor API ---
    "api_authentication": {
        "methods": ["POST", "GET"],
        "path_hints": [
            "oauth", "token", "auth", "apikey", "session", "login",
            "credential", "bearer", "refresh",
        ],
        "description": "Authenticate to the vendor API (OAuth, API key, token exchange)",
        "soc_priority": 0,
    },
}


def classify_endpoint(endpoint):
    """Classify a single endpoint into cybersecurity capability categories.

    Returns a list of matched capability names, sorted by SOC priority.
    """
    method = endpoint.get("method", "").upper()
    path = endpoint.get("path", "").lower()
    text = (endpoint.get("summary", "") + " " + endpoint.get("description", "")).lower()

    matches = []
    for cap_name, rule in CAPABILITY_RULES.items():
        method_match = method in rule["methods"]
        hint_match = any(hint in path or hint in text for hint in rule["path_hints"])

        if method_match and hint_match:
            matches.append((rule["soc_priority"], cap_name))

    # Sort by SOC priority (lower = more critical)
    matches.sort(key=lambda x: x[0])
    capabilities = [name for _, name in matches]

    # Fallback for unmatched endpoints
    if not capabilities:
        fallback = {
            "GET": "detection_retrieval",
            "POST": "alert_creation",
            "PUT": "policy_management",
            "PATCH": "policy_management",
            "DELETE": "policy_management",
        }
        if method in fallback:
            capabilities.append(fallback[method])

    return capabilities


def build_recommendations(endpoints, vendor_name=""):
    """Analyze all endpoints and produce SOC-focused integration recommendations.

    Returns a dict with capabilities, recommendations, integration_playbook,
    and a human-readable summary.
    """
    cap_groups = {}
    for ep in endpoints:
        caps = classify_endpoint(ep)
        for cap in caps:
            cap_groups.setdefault(cap, []).append(ep)

    recommendations = []
    for cap_name, eps in sorted(cap_groups.items(), key=lambda x: CAPABILITY_RULES.get(x[0], {}).get("soc_priority", 99)):
        rule = CAPABILITY_RULES.get(cap_name, {})
        rule_desc = rule.get("description", cap_name)
        priority = rule.get("soc_priority", 99)
        for ep in eps:
            recommendations.append({
                "api": f"{ep['method']} {ep['path']}",
                "capability": cap_name,
                "capability_description": rule_desc,
                "soc_priority": priority,
                "reason": ep.get("summary") or ep.get("description") or f"Matched by {ep['method']} + path pattern",
                "tags": ep.get("tags", []),
                "parameters": ep.get("parameters", []),
            })

    # Build integration playbook — ordered steps for a SOC integration
    playbook = _build_integration_playbook(cap_groups)

    # Human-readable summary
    summary_parts = []
    sorted_caps = sorted(cap_groups.items(), key=lambda x: CAPABILITY_RULES.get(x[0], {}).get("soc_priority", 99))
    for cap_name, eps in sorted_caps:
        rule = CAPABILITY_RULES.get(cap_name, {})
        priority = rule.get("soc_priority", 99)
        priority_label = {0: "SETUP", 1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}.get(priority, "INFO")
        summary_parts.append(
            f"  [{priority_label}] {cap_name} ({len(eps)} endpoints): {rule.get('description', '')}"
        )

    vendor_label = f" — {vendor_name}" if vendor_name else ""
    summary = f"Security API Capability Assessment{vendor_label}:\n" + "\n".join(summary_parts) if summary_parts else "No endpoints found."

    return {
        "vendor": vendor_name,
        "capabilities": {k: [f"{e['method']} {e['path']}" for e in v] for k, v in cap_groups.items()},
        "recommendations": recommendations,
        "integration_playbook": playbook,
        "summary": summary,
        "total_endpoints": len(endpoints),
        "total_capabilities": len(cap_groups),
    }


def _build_integration_playbook(cap_groups):
    """Generate an ordered integration playbook based on detected capabilities."""
    steps = []
    step_num = 0

    # Priority order for SOC integration
    integration_order = [
        ("api_authentication", "Authenticate to vendor API", "Set up OAuth/token auth. Store credentials securely. Implement token refresh."),
        ("detection_retrieval", "Pull detections and alerts", "Poll or stream alerts into your platform. Map severity levels. Deduplicate."),
        ("threat_hunting", "Enable event search and investigation", "Wire up query APIs for analyst investigation workflows. Build saved searches."),
        ("intel_management", "Integrate threat intelligence", "Push IOC lists (hashes, IPs, domains) to the product. Set up feed sync schedules."),
        ("response_actions", "Enable response playbooks", "Map containment actions (isolate host, block IP, kill process) to your playbook engine."),
        ("alert_creation", "Push alerts back to vendor", "Forward correlated alerts or custom detections back into the security product."),
        ("case_management", "Connect case/incident management", "Sync incidents, assignments, and status updates bidirectionally."),
        ("identity_investigation", "Wire up identity investigation", "Enable analyst lookups of user sessions, auth events, and privilege changes."),
        ("asset_management", "Sync asset inventory", "Pull host/device inventory for enrichment. Track agent health and coverage gaps."),
        ("webhook_notification", "Set up real-time webhooks", "Subscribe to event streams for real-time alerting instead of polling."),
        ("vulnerability_management", "Integrate vulnerability data", "Pull scan results and CVE data for risk-based prioritization."),
        ("log_ingestion", "Configure log forwarding", "Push logs to SIEM or set up forwarding pipelines."),
        ("policy_management", "Manage policies via API", "Automate policy updates, exclusion management, and detection rule tuning."),
        ("reporting", "Pull reports and metrics", "Integrate dashboards and executive reporting into your platform."),
    ]

    for cap_name, title, detail in integration_order:
        if cap_name in cap_groups:
            step_num += 1
            endpoints = [f"{e['method']} {e['path']}" for e in cap_groups[cap_name]]
            steps.append({
                "step": step_num,
                "title": title,
                "detail": detail,
                "capability": cap_name,
                "endpoints": endpoints,
            })

    return steps


# ---------------------------------------------------------------------------
# Claude API integration for deep analysis
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a senior cybersecurity integration architect working at a SOC platform company.
Your job is to analyze security vendor API documentation and advise on:
1. Which APIs are most valuable for SOC operations (detection, investigation, response)
2. Integration priority and sequencing
3. Specific playbook patterns (e.g., "alert -> enrich -> investigate -> contain")
4. Gotchas and rate limiting considerations
5. How to map vendor-specific concepts to standard SOC workflows

Be specific and actionable. Reference actual endpoint paths. Think like a SOC engineer
who needs to ship integrations that analysts will use daily."""


def _llm_analyze(endpoints_json, vendor_name="", use_case=""):
    """Use Claude to provide SOC-focused integration analysis."""
    try:
        import anthropic
    except ImportError:
        return None

    import os
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None

    client = anthropic.Anthropic(api_key=api_key)

    prompt = f"""Analyze this security vendor API and provide integration recommendations for our SOC platform.

Vendor: {vendor_name or "Unknown"}
{f"Use case: {use_case}" if use_case else ""}

Endpoints:
{endpoints_json}

Provide:
1. **Priority Integration Order** — Which APIs to build first for maximum SOC value
2. **Playbook Mappings** — How these APIs chain together in real incident response workflows
   (e.g., "detection fires → query events → enrich with intel → isolate host")
3. **Key Capabilities** — What this vendor API enables that's unique or critical
4. **Integration Gotchas** — Rate limits, pagination, data format quirks to watch for
5. **Coverage Gaps** — What's missing that you'd typically want from this type of vendor

Be concise and specific. Reference actual endpoint paths."""

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    return message.content[0].text


# ---------------------------------------------------------------------------
# Main Agent class
# ---------------------------------------------------------------------------

class APIRecommendationAgent:
    """Cybersecurity API Recommendation Agent.

    Ingests security vendor API documentation and produces SOC-focused
    integration recommendations, capability assessments, and playbook mappings.

    Usage:
        agent = APIRecommendationAgent()
        result = agent.analyze("crowdstrike_openapi.yaml", vendor="CrowdStrike")
        print(result["summary"])
        print(json.dumps(result["integration_playbook"], indent=2))
    """

    def __init__(self, use_llm=False):
        """
        Args:
            use_llm: If True, uses Claude API for deeper analysis.
                     Requires ANTHROPIC_API_KEY env var and `anthropic` package.
        """
        self.use_llm = use_llm
        self.parser = APIDocParser()

    def analyze(self, source, vendor="", use_case=""):
        """Analyze security vendor API documentation.

        Args:
            source: File path (.json/.yaml/.yml), raw text, or dict of an API spec.
            vendor: Name of the security vendor (e.g., "CrowdStrike", "SentinelOne").
            use_case: Optional description of what you're building.

        Returns:
            Dict with capabilities, recommendations, integration_playbook,
            summary, and optionally llm_analysis.
        """
        endpoints = self.parser.parse(source)

        if not endpoints:
            return {
                "vendor": vendor,
                "capabilities": {},
                "recommendations": [],
                "integration_playbook": [],
                "summary": "No API endpoints found in the provided documentation.",
                "total_endpoints": 0,
                "total_capabilities": 0,
            }

        result = build_recommendations(endpoints, vendor_name=vendor)

        if self.use_llm:
            trimmed = json.dumps(
                [{"method": e["method"], "path": e["path"],
                  "summary": e.get("summary", "")} for e in endpoints],
                indent=2,
            )
            llm_result = _llm_analyze(trimmed, vendor_name=vendor, use_case=use_case)
            if llm_result:
                result["llm_analysis"] = llm_result

        return result

    def analyze_and_print(self, source, vendor="", use_case=""):
        """Analyze and print human-readable output to console."""
        result = self.analyze(source, vendor=vendor, use_case=use_case)

        print("=" * 65)
        print(result["summary"])
        print(f"\nTotal endpoints scanned: {result['total_endpoints']}")
        print(f"Capability categories found: {result['total_capabilities']}")
        print("=" * 65)

        # Print integration playbook
        if result["integration_playbook"]:
            print("\nIntegration Playbook (recommended order):\n")
            for step in result["integration_playbook"]:
                print(f"  Step {step['step']}: {step['title']}")
                print(f"         {step['detail']}")
                print(f"         Endpoints: {', '.join(step['endpoints'][:3])}")
                if len(step["endpoints"]) > 3:
                    print(f"                    ... and {len(step['endpoints']) - 3} more")
                print()

        # Print recommendations grouped by capability
        print("Detailed API Recommendations:\n")
        current_cap = None
        for rec in result["recommendations"]:
            if rec["capability"] != current_cap:
                current_cap = rec["capability"]
                priority_label = {0: "SETUP", 1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}.get(rec["soc_priority"], "INFO")
                print(f"  [{priority_label}] {current_cap.upper()}: {rec['capability_description']}")
            print(f"      {rec['api']}")
            if rec["reason"]:
                print(f"        -> {rec['reason']}")

        if result.get("llm_analysis"):
            print("\n" + "=" * 65)
            print("Claude Analysis:\n")
            print(result["llm_analysis"])

        return result
