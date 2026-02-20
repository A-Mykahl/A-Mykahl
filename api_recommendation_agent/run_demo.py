#!/usr/bin/env python3
"""
Demo: Cybersecurity API Recommendation Agent

Shows the agent analyzing security vendor APIs and producing
SOC-focused integration recommendations and playbooks.

Supports: OpenAPI specs, plain text docs, URLs, and raw dicts.

Run:
    python -m api_recommendation_agent.run_demo
"""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api_recommendation_agent import APIRecommendationAgent


# ============================================================================
# DEMO 1: EDR Vendor (CrowdStrike-style OpenAPI spec)
# ============================================================================

EDR_VENDOR_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Falcon EDR API", "version": "2.0"},
    "paths": {
        # --- Auth ---
        "/oauth2/token": {
            "post": {
                "summary": "Get OAuth2 access token using client credentials",
                "tags": ["auth"],
                "requestBody": {"required": True, "content": {"application/x-www-form-urlencoded": {}}},
            }
        },
        # --- Detections ---
        "/detects/queries/detects/v1": {
            "get": {
                "summary": "Query detection IDs matching filter criteria",
                "tags": ["detections"],
                "parameters": [
                    {"name": "filter", "in": "query", "description": "FQL filter for detections"},
                    {"name": "sort", "in": "query", "description": "Sort order"},
                    {"name": "limit", "in": "query", "description": "Max results to return"},
                ],
            }
        },
        "/detects/entities/summaries/GET/v1": {
            "post": {
                "summary": "Get detection summaries by IDs",
                "tags": ["detections"],
                "requestBody": {"required": True, "content": {"application/json": {}}},
            }
        },
        "/detects/entities/detects/v2": {
            "patch": {
                "summary": "Update detection status, assignment, or visibility",
                "tags": ["detections"],
            }
        },
        # --- Incidents ---
        "/incidents/queries/incidents/v1": {
            "get": {
                "summary": "Query incident IDs with FQL filter",
                "tags": ["incidents"],
                "parameters": [
                    {"name": "filter", "in": "query", "description": "FQL filter expression"},
                ],
            }
        },
        "/incidents/entities/incidents/GET/v1": {
            "post": {
                "summary": "Get incident details by IDs",
                "tags": ["incidents"],
            }
        },
        # --- Threat Hunting / Event Search ---
        "/events/queries/events/v1": {
            "get": {
                "summary": "Search endpoint telemetry events with filters",
                "tags": ["event-search"],
                "parameters": [
                    {"name": "filter", "in": "query", "description": "Event query filter"},
                ],
            }
        },
        "/events/entities/events/v1": {
            "post": {
                "summary": "Get full event details by event IDs",
                "tags": ["event-search"],
            }
        },
        # --- Threat Intelligence / IOCs ---
        "/iocs/entities/indicators/v1": {
            "get": {
                "summary": "Get IOC indicator details",
                "tags": ["iocs"],
            },
            "post": {
                "summary": "Create custom IOC indicators (hashes, IPs, domains)",
                "tags": ["iocs"],
                "requestBody": {"required": True, "content": {"application/json": {}}},
            },
            "delete": {
                "summary": "Delete IOC indicators by ID",
                "tags": ["iocs"],
            },
        },
        "/intel/queries/indicators/v1": {
            "get": {
                "summary": "Query threat intel indicators from CrowdStrike feed",
                "tags": ["intel"],
                "parameters": [
                    {"name": "filter", "in": "query", "description": "Intel indicator filter"},
                ],
            }
        },
        "/intel/entities/reports/v1": {
            "get": {
                "summary": "Get threat intelligence reports",
                "tags": ["intel"],
            }
        },
        # --- Response Actions ---
        "/devices/entities/devices-actions/v2": {
            "post": {
                "summary": "Take action on devices: contain host, lift containment, hide host",
                "tags": ["response"],
                "parameters": [
                    {"name": "action_name", "in": "query",
                     "description": "Action: contain, lift_containment, hide_host, unhide_host"},
                ],
                "requestBody": {"required": True, "content": {"application/json": {}}},
            }
        },
        "/real-time-response/entities/sessions/v1": {
            "post": {
                "summary": "Initialize a Real Time Response session on a host",
                "tags": ["response"],
            }
        },
        "/real-time-response/entities/command/v1": {
            "post": {
                "summary": "Execute RTR command on host (kill process, quarantine file, run script)",
                "tags": ["response"],
            }
        },
        # --- Host / Asset Management ---
        "/devices/queries/devices/v1": {
            "get": {
                "summary": "Search for hosts/devices by filter",
                "tags": ["hosts"],
                "parameters": [
                    {"name": "filter", "in": "query", "description": "FQL host filter"},
                ],
            }
        },
        "/devices/entities/devices/v2": {
            "post": {
                "summary": "Get detailed host information by device IDs",
                "tags": ["hosts"],
            }
        },
        # --- Vulnerability / Spotlight ---
        "/spotlight/queries/vulnerabilities/v1": {
            "get": {
                "summary": "Query vulnerability IDs by CVE, host, or severity",
                "tags": ["vulnerabilities"],
                "parameters": [
                    {"name": "filter", "in": "query", "description": "Vulnerability filter"},
                ],
            }
        },
        "/spotlight/entities/vulnerabilities/v2": {
            "get": {
                "summary": "Get vulnerability details including CVE data and remediation",
                "tags": ["vulnerabilities"],
            }
        },
        # --- Prevention Policies ---
        "/policy/queries/prevention/v1": {
            "get": {
                "summary": "Query prevention policy IDs",
                "tags": ["policies"],
            }
        },
        "/policy/entities/prevention/v1": {
            "put": {
                "summary": "Update prevention policy settings",
                "tags": ["policies"],
            }
        },
    },
}


# ============================================================================
# DEMO 2: SIEM Vendor (Splunk-style plain-text API doc)
# ============================================================================

SIEM_VENDOR_TEXT = """
Splunk Enterprise Security REST API

Authentication:
POST /services/auth/login
  Authenticate and retrieve a session token for subsequent API calls.

Search & Investigation:
POST /services/search/jobs
  Create a new search job. Accepts SPL query string. Use for threat hunting and event investigation.

GET /services/search/jobs/{search_id}
  Get search job status and metadata.

GET /services/search/jobs/{search_id}/results
  Retrieve search results. Supports JSON/CSV output. Use for pulling event data.

Alerts & Notable Events:
GET /services/alerts/fired_alerts
  List all triggered alerts from correlation searches.

POST /services/notable_update
  Update notable event status (New, In Progress, Closed), urgency, owner assignment.

POST /services/alerts/actions
  Create a new alert action or trigger a response workflow.

Threat Intelligence:
POST /services/data/threat_intel/upload
  Upload threat intel IOC list (CSV with IPs, domains, hashes) to KV store lookup.

GET /services/data/threat_intel/collections
  List available threat intel collections and their contents.

POST /services/data/inputs/oneshot
  Ingest a one-shot log event or batch of events into an index.

Data Ingestion:
POST /services/collectors/event
  Send events to HTTP Event Collector (HEC) for SIEM ingestion.

GET /services/data/indexes
  List all available indexes and their properties.

Dashboards & Reporting:
GET /services/saved/searches
  List all saved searches, reports, and scheduled correlation searches.

POST /services/saved/searches
  Create a new saved search or correlation rule.

GET /services/dashboards
  List available dashboards and their panels.
"""


# ============================================================================
# DEMO 3: SOAR Platform (Palo Alto XSOAR-style)
# ============================================================================

SOAR_VENDOR_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "XSOAR API", "version": "6.0"},
    "paths": {
        "/login": {
            "post": {"summary": "Authenticate to XSOAR and get API token", "tags": ["auth"]},
        },
        "/incidents/search": {
            "post": {
                "summary": "Search incidents with query filters, date range, and severity",
                "tags": ["incidents"],
                "requestBody": {"required": True, "content": {"application/json": {}}},
            }
        },
        "/incident": {
            "post": {
                "summary": "Create a new incident with type, severity, and custom fields",
                "tags": ["incidents"],
            }
        },
        "/incident/{id}": {
            "get": {"summary": "Get full incident details including timeline and evidence", "tags": ["incidents"]},
            "put": {"summary": "Update incident status, owner, severity, or close reason", "tags": ["incidents"]},
        },
        "/incident/{id}/investigation": {
            "get": {"summary": "Get investigation war room entries and analyst actions", "tags": ["investigation"]},
        },
        "/indicators/search": {
            "post": {
                "summary": "Search IOC indicators (IP, domain, hash, URL) with reputation scores",
                "tags": ["indicators"],
            }
        },
        "/indicator/create": {
            "post": {
                "summary": "Create a new IOC indicator with type, value, and reputation",
                "tags": ["indicators"],
            }
        },
        "/indicator/blocklist": {
            "post": {
                "summary": "Push indicators to EDR/firewall blocklist via playbook",
                "tags": ["indicators", "response"],
            }
        },
        "/playbook/execute": {
            "post": {
                "summary": "Trigger a playbook: isolate host, block IP, enrich indicators, notify analyst",
                "tags": ["playbooks"],
                "requestBody": {"required": True, "content": {"application/json": {}}},
            }
        },
        "/playbook/{id}/status": {
            "get": {"summary": "Get playbook execution status and task results", "tags": ["playbooks"]},
        },
        "/automation/scripts": {
            "get": {"summary": "List available automation scripts for response actions", "tags": ["automation"]},
            "post": {"summary": "Create a new automation script", "tags": ["automation"]},
        },
        "/evidence/{incident_id}": {
            "post": {
                "summary": "Upload forensic evidence file (PCAP, memory dump, logs) to incident",
                "tags": ["evidence"],
            }
        },
        "/users": {
            "get": {"summary": "List all XSOAR users and their roles for assignment", "tags": ["admin"]},
        },
    },
}


def demo_edr():
    """Analyze an EDR vendor API (CrowdStrike-style)."""
    print("\n" + "#" * 65)
    print("# DEMO 1: EDR Vendor API Analysis (CrowdStrike-style)")
    print("#" * 65 + "\n")

    agent = APIRecommendationAgent(use_llm=False)
    result = agent.analyze_and_print(EDR_VENDOR_SPEC, vendor="FalconEDR")

    print("\n--- Platform Integration JSON ---\n")
    print(json.dumps({
        "vendor": result["vendor"],
        "capabilities": result["capabilities"],
        "integration_playbook": result["integration_playbook"],
    }, indent=2))


def demo_siem():
    """Analyze a SIEM vendor API from plain-text docs (Splunk-style)."""
    print("\n\n" + "#" * 65)
    print("# DEMO 2: SIEM Vendor API Analysis (Splunk-style text doc)")
    print("#" * 65 + "\n")

    agent = APIRecommendationAgent(use_llm=False)
    agent.analyze_and_print(SIEM_VENDOR_TEXT, vendor="SplunkES")


def demo_soar():
    """Analyze a SOAR platform API (XSOAR-style)."""
    print("\n\n" + "#" * 65)
    print("# DEMO 3: SOAR Platform API Analysis (XSOAR-style)")
    print("#" * 65 + "\n")

    agent = APIRecommendationAgent(use_llm=False)
    agent.analyze_and_print(SOAR_VENDOR_SPEC, vendor="XSOAR")


def demo_url():
    """Show how to analyze a vendor API from a URL."""
    print("\n\n" + "#" * 65)
    print("# DEMO 4: Analyzing API Docs from a URL")
    print("#" * 65 + "\n")
    print("Usage (pass any vendor API doc URL):\n")
    print("  from api_recommendation_agent import APIRecommendationAgent")
    print("  agent = APIRecommendationAgent()")
    print('  result = agent.analyze("https://assets.falcon.crowdstrike.com/...", vendor="CrowdStrike")')
    print('  result = agent.analyze("https://docs.sentinelone.com/api/...", vendor="SentinelOne")')
    print()
    print("  The parser auto-detects format:")
    print("    - JSON/YAML URL  -> parsed as OpenAPI spec")
    print("    - HTML doc page  -> stripped to text, endpoints extracted")
    print("    - Raw text       -> heuristic endpoint extraction")


def demo_llm():
    """Show LLM-enhanced analysis (requires ANTHROPIC_API_KEY)."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("\n\n--- Skipping Claude analysis demo (set ANTHROPIC_API_KEY to enable) ---")
        print("    With Claude enabled, the agent provides:")
        print("    - Priority integration ordering with rationale")
        print("    - Incident response playbook chain mappings")
        print("    - Vendor-specific gotchas and rate limit advice")
        print("    - Coverage gap analysis vs. typical SOC needs")
        return

    print("\n\n" + "#" * 65)
    print("# DEMO 5: Claude-Enhanced SOC Integration Analysis")
    print("#" * 65 + "\n")

    agent = APIRecommendationAgent(use_llm=True)
    agent.analyze_and_print(
        EDR_VENDOR_SPEC,
        vendor="FalconEDR",
        use_case=(
            "We're building a SOC platform that needs to pull detections, "
            "enable analyst investigation with event search, push IOC blocklists, "
            "and trigger host isolation from playbooks."
        ),
    )


if __name__ == "__main__":
    demo_edr()
    demo_siem()
    demo_soar()
    demo_url()
    demo_llm()

    print("\n" + "=" * 65)
    print("Quick Start:\n")
    print("  from api_recommendation_agent import APIRecommendationAgent\n")
    print("  agent = APIRecommendationAgent(use_llm=True)  # or False for offline\n")
    print("  # From an OpenAPI spec file:")
    print('  result = agent.analyze("vendor_api.yaml", vendor="CrowdStrike")\n')
    print("  # From a documentation URL:")
    print('  result = agent.analyze("https://docs.vendor.com/api", vendor="SentinelOne")\n')
    print("  # From raw text docs:")
    print('  result = agent.analyze("""')
    print("    GET /detections  - List all detections")
    print("    POST /iocs       - Push IOC indicators")
    print('  """, vendor="CustomVendor")\n')
    print("  # Key outputs:")
    print('  result["capabilities"]         # What the API can do')
    print('  result["integration_playbook"] # Ordered steps to integrate')
    print('  result["recommendations"]      # Every endpoint with SOC context')
    print('  result["llm_analysis"]         # Claude deep analysis (if enabled)')
