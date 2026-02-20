#!/usr/bin/env python3
"""
Demo: Cybersecurity API Recommendation Agent

Shows the agent analyzing security vendor APIs and producing
SOC-focused integration recommendations, playbooks, source/field
discovery, and multi-method integration detection.

Supports: OpenAPI specs, plain text docs, URLs, GraphQL, webhooks.

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
#   Includes source/field discovery endpoints
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
        # --- Data Source & Field Discovery ---
        "/discover/queries/data-sources/v1": {
            "get": {
                "summary": "List available data sources and log source types connected to the platform",
                "tags": ["discover"],
                "parameters": [
                    {"name": "filter", "in": "query", "description": "Filter data sources by type or status"},
                ],
            }
        },
        "/discover/entities/data-sources/v1": {
            "get": {
                "summary": "Get data source details including ingestion status and event count",
                "tags": ["discover"],
            }
        },
        "/events/entities/fields/v1": {
            "get": {
                "summary": "List all available event fields, types, and descriptions for telemetry data",
                "tags": ["event-search", "schema"],
            }
        },
        "/events/entities/field-metadata/v1": {
            "get": {
                "summary": "Get field metadata including data type, searchable flag, and enum values",
                "tags": ["event-search", "schema"],
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
        # --- Streaming (Event Stream) ---
        "/sensors/entities/datafeed/v2": {
            "get": {
                "summary": "Get event stream URL for realtime streaming of detection and audit events",
                "tags": ["streaming"],
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
#   Includes source/field discovery and webhook support
# ============================================================================

SIEM_VENDOR_TEXT = """
Splunk Enterprise Security REST API

Authentication:
POST /services/auth/login
  Authenticate and retrieve a session token for subsequent API calls.

Data Source Discovery:
GET /services/data/inputs
  List all configured data inputs (sources) including file monitors, network inputs, scripted inputs.

GET /services/data/inputs/{type}
  Get data source details by input type (monitor, tcp, udp, script, http).

GET /services/data/indexes
  List all available indexes and their properties. Each index represents a data source category.

GET /services/data/indexes/{name}
  Get detailed index metadata: event count, earliest/latest time, field summary.

Field Discovery:
GET /services/search/fields
  List all indexed fields across all sources with type information and frequency.

GET /services/search/fields/{field_name}
  Get field details: data type, distinct values, sources where it appears.

POST /services/search/jobs
  Run 'metadata type=sources' or '| fieldsummary' SPL to discover sources and field schemas dynamically.

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

Webhooks & Real-time:
POST /services/alerts/webhook
  Configure a webhook callback URL for real-time alert delivery.

POST /services/data/inputs/oneshot
  Ingest a one-shot log event or batch of events into an index.

Data Ingestion:
POST /services/collectors/event
  Send events to HTTP Event Collector (HEC) for SIEM ingestion.

Dashboards & Reporting:
GET /services/saved/searches
  List all saved searches, reports, and scheduled correlation searches.

POST /services/saved/searches
  Create a new saved search or correlation rule.

GET /services/dashboards
  List available dashboards and their panels.
"""


# ============================================================================
# DEMO 3: XDR Platform with GraphQL + webhooks + REST (multi-method)
# ============================================================================

XDR_MULTI_METHOD_TEXT = """
SecureXDR Platform API Documentation

Authentication:
POST /api/v2/auth/token
  Exchange API key for bearer token. Tokens expire after 1 hour.

=== REST API Endpoints ===

Source & Connector Management:
GET /api/v2/sources
  List all connected data sources (EDR, firewall, email gateway, cloud, identity).

GET /api/v2/sources/{source_id}/fields
  Get available fields and schema for a specific data source.

GET /api/v2/sources/{source_id}/field-mappings
  Get field mapping definitions showing how source fields map to normalized schema.

POST /api/v2/sources/{source_id}/test
  Test connectivity to a data source and validate field mappings.

Detection & Alerts:
GET /api/v2/detections
  List detections with filters for severity, source, status, time range.

GET /api/v2/detections/{id}
  Get detection details including matched rule, evidence, and timeline.

POST /api/v2/detections
  Create a custom detection or import detection from external source.

Investigation:
POST /api/v2/investigate/query
  Run a cross-source investigation query across all connected data sources.

GET /api/v2/investigate/events
  Search raw events across all sources with unified query language.

Response Actions:
POST /api/v2/response/isolate-host
  Isolate a compromised host from the network via EDR integration.

POST /api/v2/response/block-ioc
  Push IOC to all connected blocking points (firewall, EDR, proxy, email gateway).

POST /api/v2/response/disable-account
  Disable a user account across connected identity providers.

POST /api/v2/response/playbook/execute
  Execute a response playbook with parameters (host ID, IOC list, etc).

Threat Intel:
GET /api/v2/intel/iocs
  Get all IOC indicators with reputation scores and source attribution.

POST /api/v2/intel/iocs/bulk
  Bulk upload IOC list (JSON array of hashes, IPs, domains, URLs).

POST /api/v2/intel/enrichment
  Enrich an observable (IP, hash, domain) with threat intel from all feeds.

=== GraphQL API ===

query getDetectionDetails {
  Fetch full detection details including related events, entities, and MITRE mappings.

query searchEvents {
  Cross-source event search with field-level filtering and aggregation.

query getSourceSchema {
  Get complete field schema for any connected source, including data types and descriptions.

mutation createAlert {
  Create a custom alert with severity, description, entities, and evidence.

mutation updateIncident {
  Update incident status, assignment, priority, or add investigation notes.

subscription detectionStream {
  Subscribe to real-time detection stream via WebSocket for immediate alerting.

=== Webhook Configuration ===

POST /api/v2/webhooks
  Register a webhook endpoint for real-time event delivery.

GET /api/v2/webhooks
  List all configured webhook subscriptions and their status.

DELETE /api/v2/webhooks/{id}
  Remove a webhook subscription.

Webhook events delivered:
  - detection.created: New detection fired
  - incident.updated: Incident status changed
  - response.completed: Response action finished
"""


# ============================================================================
# DEMO 4: SOAR Platform (XSOAR-style)
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
        "/incident/fields": {
            "get": {"summary": "Get all incident field definitions, types, and mappings", "tags": ["schema"]},
        },
        "/incident/types": {
            "get": {"summary": "List available incident types and their associated field schemas", "tags": ["schema"]},
        },
        "/integrations": {
            "get": {"summary": "List all configured integration instances (data sources and connectors)", "tags": ["integrations"]},
        },
        "/integrations/{id}/test": {
            "post": {"summary": "Test connectivity to an integration source", "tags": ["integrations"]},
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
    """Analyze an EDR vendor API with source/field discovery."""
    print("\n" + "#" * 65)
    print("# DEMO 1: EDR Vendor (source/field discovery + streaming)")
    print("#" * 65 + "\n")

    agent = APIRecommendationAgent(use_llm=False)
    result = agent.analyze_and_print(EDR_VENDOR_SPEC, vendor="FalconEDR")

    print("\n--- Platform Integration JSON (abridged) ---\n")
    print(json.dumps({
        "vendor": result["vendor"],
        "integration_methods": result["integration_methods"],
        "capabilities": list(result["capabilities"].keys()),
        "total_suggested": result["total_suggested"],
    }, indent=2))


def demo_siem():
    """Analyze a SIEM vendor API with source/field and webhook support."""
    print("\n\n" + "#" * 65)
    print("# DEMO 2: SIEM Vendor (source/field discovery + webhooks)")
    print("#" * 65 + "\n")

    agent = APIRecommendationAgent(use_llm=False)
    agent.analyze_and_print(SIEM_VENDOR_TEXT, vendor="SplunkES")


def demo_xdr_multi():
    """Analyze an XDR platform with REST + GraphQL + webhooks + streaming."""
    print("\n\n" + "#" * 65)
    print("# DEMO 3: XDR Platform (REST + GraphQL + Webhook + Streaming)")
    print("#" * 65 + "\n")

    agent = APIRecommendationAgent(use_llm=False)
    result = agent.analyze_and_print(XDR_MULTI_METHOD_TEXT, vendor="SecureXDR")

    print("\n--- Integration Methods Breakdown ---\n")
    print(json.dumps(result["integration_methods"], indent=2))


def demo_soar():
    """Analyze a SOAR platform API with field/integration discovery."""
    print("\n\n" + "#" * 65)
    print("# DEMO 4: SOAR Platform (field schemas + integrations)")
    print("#" * 65 + "\n")

    agent = APIRecommendationAgent(use_llm=False)
    agent.analyze_and_print(SOAR_VENDOR_SPEC, vendor="XSOAR")


def demo_llm():
    """Show LLM-enhanced analysis (requires ANTHROPIC_API_KEY)."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("\n\n--- Skipping Claude analysis demo (set ANTHROPIC_API_KEY to enable) ---")
        print("    With Claude enabled, the agent additionally provides:")
        print("    - Source/field discovery analysis and gap identification")
        print("    - Integration method recommendations per capability")
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
            "discover data sources and their field schemas, enable analyst "
            "investigation with event search, push IOC blocklists, and "
            "trigger host isolation from playbooks."
        ),
    )


if __name__ == "__main__":
    demo_edr()
    demo_siem()
    demo_xdr_multi()
    demo_soar()
    demo_llm()

    print("\n" + "=" * 65)
    print("Quick Start:\n")
    print("  from api_recommendation_agent import APIRecommendationAgent\n")
    print("  agent = APIRecommendationAgent(use_llm=True)  # or False for offline\n")
    print("  # From an OpenAPI spec file:")
    print('  result = agent.analyze("vendor_api.yaml", vendor="CrowdStrike")\n')
    print("  # From a documentation URL:")
    print('  result = agent.analyze("https://docs.vendor.com/api", vendor="SentinelOne")\n')
    print("  # From raw text / markdown docs:")
    print('  result = agent.analyze(open("vendor_docs.md").read(), vendor="PaloAlto")\n')
    print("  # Key outputs:")
    print('  result["capabilities"]         # Confirmed capabilities by category')
    print('  result["suggested_apis"]       # Uncertain matches — review these')
    print('  result["integration_methods"]  # REST, GraphQL, webhook, streaming, etc.')
    print('  result["integration_playbook"] # Ordered steps to integrate')
    print('  result["recommendations"]      # Every endpoint with SOC context')
    print('  result["llm_analysis"]         # Claude deep analysis (if enabled)')
