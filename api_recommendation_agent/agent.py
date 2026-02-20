"""
Core API Recommendation Agent — Cybersecurity Edition.

Takes parsed API endpoints from security vendor documentation,
classifies them into SOC/IR capability categories, detects integration
methods (REST, GraphQL, webhook, streaming, etc.), flags suggested APIs
for uncertain matches, and produces actionable recommendations.

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
    # --- Data Source & Field Discovery ---
    "source_discovery": {
        "methods": ["GET", "POST"],
        "path_hints": [
            "source", "sources", "log_source", "logsource", "data_source",
            "datasource", "input", "inputs", "connector", "integration",
            "feed", "collector", "receiver", "origin", "tenant",
            "sensor", "forwarder", "index", "indexes", "repository",
        ],
        "description": "Discover available data sources, log sources, connectors, and ingestion points",
        "soc_priority": 1,
    },
    "field_schema": {
        "methods": ["GET", "POST"],
        "path_hints": [
            "field", "fields", "schema", "column", "attribute", "property",
            "metadata", "mapping", "type", "definition", "model", "describe",
            "introspect", "catalog", "dictionary", "enum", "taxonomy",
            "label", "tag", "key",
        ],
        "description": "Get field names, schemas, data types, and metadata for source data",
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

# Priority labels for display
PRIORITY_LABELS = {0: "SETUP", 1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}


# ---------------------------------------------------------------------------
# Integration method detection
# ---------------------------------------------------------------------------

def detect_integration_method(endpoint):
    """Detect what integration method an endpoint uses.

    Returns a string: 'rest', 'graphql', 'webhook', 'streaming',
    'websocket', 'grpc', or 'soap'.
    """
    path = endpoint.get("path", "").lower()
    text = (endpoint.get("summary", "") + " " + endpoint.get("description", "")).lower()
    method = endpoint.get("method", "").upper()
    tags = " ".join(endpoint.get("tags", [])).lower()
    all_text = f"{path} {text} {tags}"

    if "graphql" in all_text or "query {" in text or "mutation {" in text:
        return "graphql"
    if "websocket" in all_text or "wss:" in all_text or "ws:" in all_text:
        return "websocket"
    if "grpc" in all_text or "protobuf" in all_text:
        return "grpc"
    if "soap" in all_text or "wsdl" in all_text or "xml-rpc" in all_text:
        return "soap"
    if any(kw in all_text for kw in ["stream", "sse", "server-sent", "event-stream", "firehose", "realtime"]):
        return "streaming"
    if any(kw in all_text for kw in ["webhook", "hook", "callback", "subscribe", "push notification"]):
        return "webhook"
    return "rest"


def detect_all_methods(endpoints):
    """Summarize all integration methods found across endpoints.

    Returns a dict of {method_name: [endpoints using it]}.
    """
    methods = {}
    for ep in endpoints:
        m = detect_integration_method(ep)
        methods.setdefault(m, []).append(f"{ep['method']} {ep['path']}")
    return methods


# ---------------------------------------------------------------------------
# Endpoint classification
# ---------------------------------------------------------------------------

def classify_endpoint(endpoint):
    """Classify a single endpoint into cybersecurity capability categories.

    Returns a tuple: (matched_capabilities, confidence).
    confidence is 'strong' if method+path both matched,
    'suggested' if only text/description matched but method didn't align perfectly.
    """
    method = endpoint.get("method", "").upper()
    path = endpoint.get("path", "").lower()
    text = (endpoint.get("summary", "") + " " + endpoint.get("description", "")).lower()

    strong_matches = []
    suggested_matches = []

    for cap_name, rule in CAPABILITY_RULES.items():
        method_match = method in rule["methods"]
        path_match = any(hint in path for hint in rule["path_hints"])
        text_match = any(hint in text for hint in rule["path_hints"])

        if method_match and path_match:
            strong_matches.append((rule["soc_priority"], cap_name))
        elif method_match and text_match:
            strong_matches.append((rule["soc_priority"], cap_name))
        elif path_match or text_match:
            # Path or description matches but HTTP method doesn't align —
            # still worth surfacing as a suggestion
            suggested_matches.append((rule["soc_priority"], cap_name))

    strong_matches.sort(key=lambda x: x[0])
    suggested_matches.sort(key=lambda x: x[0])

    if strong_matches:
        return [name for _, name in strong_matches], "strong"

    if suggested_matches:
        return [name for _, name in suggested_matches], "suggested"

    # No match at all — still surface it as uncategorized suggestion
    return ["uncategorized"], "suggested"


def build_recommendations(endpoints, vendor_name=""):
    """Analyze all endpoints and produce SOC-focused integration recommendations.

    Returns a dict with capabilities, recommendations, suggested_apis,
    integration_methods, integration_playbook, and a human-readable summary.
    """
    cap_groups = {}
    suggested_apis = []
    all_recs = []

    for ep in endpoints:
        caps, confidence = classify_endpoint(ep)
        integration_method = detect_integration_method(ep)

        for cap in caps:
            rec = {
                "api": f"{ep['method']} {ep['path']}",
                "capability": cap,
                "capability_description": CAPABILITY_RULES.get(cap, {}).get("description", cap),
                "soc_priority": CAPABILITY_RULES.get(cap, {}).get("soc_priority", 99),
                "confidence": confidence,
                "integration_method": integration_method,
                "reason": ep.get("summary") or ep.get("description") or f"Matched by {ep['method']} + path pattern",
                "tags": ep.get("tags", []),
                "parameters": ep.get("parameters", []),
            }

            if confidence == "strong":
                cap_groups.setdefault(cap, []).append(ep)
                all_recs.append(rec)
            else:
                suggested_apis.append(rec)

    # Sort confirmed recommendations by SOC priority
    all_recs.sort(key=lambda r: (r["soc_priority"], r["capability"]))

    # Build integration playbook from confirmed capabilities
    playbook = _build_integration_playbook(cap_groups)

    # Detect integration methods across all endpoints
    integration_methods = detect_all_methods(endpoints)

    # Human-readable summary
    summary_parts = []
    sorted_caps = sorted(cap_groups.items(), key=lambda x: CAPABILITY_RULES.get(x[0], {}).get("soc_priority", 99))
    for cap_name, eps in sorted_caps:
        rule = CAPABILITY_RULES.get(cap_name, {})
        priority = rule.get("soc_priority", 99)
        summary_parts.append(
            f"  [{PRIORITY_LABELS.get(priority, 'INFO')}] {cap_name} ({len(eps)} endpoints): {rule.get('description', '')}"
        )

    vendor_label = f" — {vendor_name}" if vendor_name else ""
    summary = f"Security API Capability Assessment{vendor_label}:\n" + "\n".join(summary_parts) if summary_parts else "No endpoints found."

    return {
        "vendor": vendor_name,
        "capabilities": {k: [f"{e['method']} {e['path']}" for e in v] for k, v in cap_groups.items()},
        "recommendations": all_recs,
        "suggested_apis": suggested_apis,
        "integration_methods": integration_methods,
        "integration_playbook": playbook,
        "summary": summary,
        "total_endpoints": len(endpoints),
        "total_capabilities": len(cap_groups),
        "total_suggested": len(suggested_apis),
    }


def _build_integration_playbook(cap_groups):
    """Generate an ordered integration playbook based on detected capabilities."""
    steps = []
    step_num = 0

    integration_order = [
        ("api_authentication", "Authenticate to vendor API",
         "Set up OAuth/token auth. Store credentials securely. Implement token refresh."),
        ("source_discovery", "Discover available data sources",
         "Query available log sources, connectors, and data feeds. Map source names to your platform's taxonomy."),
        ("field_schema", "Map fields and schemas",
         "Pull field names, types, and metadata for each source. Build field mappings for normalization."),
        ("detection_retrieval", "Pull detections and alerts",
         "Poll or stream alerts into your platform. Map severity levels. Deduplicate."),
        ("threat_hunting", "Enable event search and investigation",
         "Wire up query APIs for analyst investigation workflows. Build saved searches."),
        ("intel_management", "Integrate threat intelligence",
         "Push IOC lists (hashes, IPs, domains) to the product. Set up feed sync schedules."),
        ("response_actions", "Enable response playbooks",
         "Map containment actions (isolate host, block IP, kill process) to your playbook engine."),
        ("alert_creation", "Push alerts back to vendor",
         "Forward correlated alerts or custom detections back into the security product."),
        ("case_management", "Connect case/incident management",
         "Sync incidents, assignments, and status updates bidirectionally."),
        ("identity_investigation", "Wire up identity investigation",
         "Enable analyst lookups of user sessions, auth events, and privilege changes."),
        ("asset_management", "Sync asset inventory",
         "Pull host/device inventory for enrichment. Track agent health and coverage gaps."),
        ("webhook_notification", "Set up real-time webhooks",
         "Subscribe to event streams for real-time alerting instead of polling."),
        ("vulnerability_management", "Integrate vulnerability data",
         "Pull scan results and CVE data for risk-based prioritization."),
        ("log_ingestion", "Configure log forwarding",
         "Push logs to SIEM or set up forwarding pipelines."),
        ("policy_management", "Manage policies via API",
         "Automate policy updates, exclusion management, and detection rule tuning."),
        ("reporting", "Pull reports and metrics",
         "Integrate dashboards and executive reporting into your platform."),
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
4. Source and field discovery — how to enumerate what data sources and fields are available
5. Integration methods — REST, GraphQL, webhook, streaming, gRPC — and when to use each
6. Gotchas: rate limiting, pagination, data format quirks
7. How to map vendor-specific concepts to standard SOC workflows

When you see endpoints that could serve multiple purposes, call them out as suggested uses.
If you think the vendor likely has additional APIs not shown (e.g., missing source/field
discovery, missing webhook support), note the gaps and suggest what to look for.

Be specific and actionable. Reference actual endpoint paths. Think like a SOC engineer
who needs to ship integrations that analysts will use daily."""


def _llm_analyze(endpoints_json, integration_methods, vendor_name="", use_case=""):
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

    methods_summary = ", ".join(f"{m} ({len(eps)} endpoints)" for m, eps in integration_methods.items())

    prompt = f"""Analyze this security vendor API and provide integration recommendations for our SOC platform.

Vendor: {vendor_name or "Unknown"}
Integration methods detected: {methods_summary}
{f"Use case: {use_case}" if use_case else ""}

Endpoints:
{endpoints_json}

Provide:
1. **Priority Integration Order** — Which APIs to build first for maximum SOC value
2. **Source & Field Discovery** — Which endpoints let us enumerate data sources and their field schemas.
   If none are present, flag this as a gap and suggest how to discover them.
3. **Playbook Mappings** — How these APIs chain together in real IR workflows
   (e.g., "detection fires → get source fields → query events → enrich with intel → isolate host")
4. **Integration Methods** — For each capability, which integration method is best
   (REST polling, webhook push, GraphQL query, streaming, etc.) and why
5. **Suggested API Uses** — Any endpoints that could serve double duty or have non-obvious uses
   (e.g., a generic query endpoint that can also be used for source enumeration)
6. **Coverage Gaps** — What's missing that you'd typically want from this type of vendor

Be concise and specific. Reference actual endpoint paths."""

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2500,
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
    integration recommendations, capability assessments, playbook mappings,
    and integration method analysis.

    Accepts input as: OpenAPI spec (file/dict), plain text docs, or a URL.
    Detects REST, GraphQL, webhook, streaming, WebSocket, gRPC, and SOAP.

    Usage:
        agent = APIRecommendationAgent()
        result = agent.analyze("crowdstrike_openapi.yaml", vendor="CrowdStrike")
        print(result["summary"])
        print(json.dumps(result["integration_playbook"], indent=2))
        print(json.dumps(result["suggested_apis"], indent=2))
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
            source: File path, URL, raw text, or dict of an API spec.
            vendor: Name of the security vendor (e.g., "CrowdStrike", "SentinelOne").
            use_case: Optional description of what you're building.

        Returns:
            Dict with: capabilities, recommendations, suggested_apis,
            integration_methods, integration_playbook, summary,
            and optionally llm_analysis.
        """
        endpoints = self.parser.parse(source)

        if not endpoints:
            return {
                "vendor": vendor,
                "capabilities": {},
                "recommendations": [],
                "suggested_apis": [],
                "integration_methods": {},
                "integration_playbook": [],
                "summary": "No API endpoints found in the provided documentation.",
                "total_endpoints": 0,
                "total_capabilities": 0,
                "total_suggested": 0,
            }

        result = build_recommendations(endpoints, vendor_name=vendor)

        if self.use_llm:
            trimmed = json.dumps(
                [{"method": e["method"], "path": e["path"],
                  "summary": e.get("summary", ""),
                  "integration_method": detect_integration_method(e)}
                 for e in endpoints],
                indent=2,
            )
            llm_result = _llm_analyze(
                trimmed,
                integration_methods=result["integration_methods"],
                vendor_name=vendor,
                use_case=use_case,
            )
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
        print(f"Suggested/review APIs: {result['total_suggested']}")
        print("=" * 65)

        # Print integration methods
        if result["integration_methods"]:
            print("\nIntegration Methods Detected:\n")
            for method_name, eps in sorted(result["integration_methods"].items()):
                print(f"  {method_name.upper()} ({len(eps)} endpoints)")
                for ep in eps[:3]:
                    print(f"      {ep}")
                if len(eps) > 3:
                    print(f"      ... and {len(eps) - 3} more")
            print()

        # Print integration playbook
        if result["integration_playbook"]:
            print("Integration Playbook (recommended order):\n")
            for step in result["integration_playbook"]:
                print(f"  Step {step['step']}: {step['title']}")
                print(f"         {step['detail']}")
                print(f"         Endpoints: {', '.join(step['endpoints'][:3])}")
                if len(step["endpoints"]) > 3:
                    print(f"                    ... and {len(step['endpoints']) - 3} more")
                print()

        # Print confirmed recommendations grouped by capability
        print("Confirmed API Recommendations:\n")
        current_cap = None
        for rec in result["recommendations"]:
            if rec["capability"] != current_cap:
                current_cap = rec["capability"]
                priority_label = PRIORITY_LABELS.get(rec["soc_priority"], "INFO")
                print(f"  [{priority_label}] {current_cap.upper()}: {rec['capability_description']}")
            method_tag = f" [{rec['integration_method']}]" if rec["integration_method"] != "rest" else ""
            print(f"      {rec['api']}{method_tag}")
            if rec["reason"]:
                print(f"        -> {rec['reason']}")

        # Print suggested/uncertain APIs
        if result["suggested_apis"]:
            print(f"\nSuggested APIs (review for potential use):\n")
            for rec in result["suggested_apis"]:
                cap_desc = rec["capability_description"]
                if rec["capability"] == "uncategorized":
                    cap_desc = "Could not auto-classify — review manually"
                method_tag = f" [{rec['integration_method']}]" if rec["integration_method"] != "rest" else ""
                print(f"  [SUGGESTED] {rec['api']}{method_tag}")
                print(f"      Possible use: {rec['capability']} — {cap_desc}")
                if rec["reason"]:
                    print(f"      Context: {rec['reason']}")

        if result.get("llm_analysis"):
            print("\n" + "=" * 65)
            print("Claude Analysis:\n")
            print(result["llm_analysis"])

        return result
