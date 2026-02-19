"""
Core API Recommendation Agent.

Takes parsed API endpoints, classifies their capabilities,
and produces recommendations for which APIs to use and why.
Can optionally use an LLM (Anthropic Claude) for richer analysis,
but works fully offline with rule-based classification.
"""

import json
from .parser import APIDocParser

# ---------------------------------------------------------------------------
# Capability classification rules (no LLM needed)
# ---------------------------------------------------------------------------

CAPABILITY_RULES = {
    "data_retrieval": {
        "methods": ["GET"],
        "path_hints": ["list", "search", "query", "find", "fetch", "index"],
        "description": "Fetch or list resources",
    },
    "creation": {
        "methods": ["POST"],
        "path_hints": ["create", "add", "new", "register", "sign"],
        "description": "Create new resources",
    },
    "update": {
        "methods": ["PUT", "PATCH"],
        "path_hints": ["update", "edit", "modify", "change"],
        "description": "Update existing resources",
    },
    "deletion": {
        "methods": ["DELETE"],
        "path_hints": ["delete", "remove", "destroy"],
        "description": "Delete resources",
    },
    "authentication": {
        "methods": ["POST"],
        "path_hints": ["auth", "login", "token", "oauth", "session", "signin"],
        "description": "Authentication and session management",
    },
    "search": {
        "methods": ["GET", "POST"],
        "path_hints": ["search", "query", "filter", "lookup", "find"],
        "description": "Search and filtering capabilities",
    },
    "file_handling": {
        "methods": ["POST", "PUT", "GET"],
        "path_hints": ["upload", "download", "file", "media", "image", "asset", "blob"],
        "description": "File upload, download, or media management",
    },
    "webhooks": {
        "methods": ["POST", "PUT", "DELETE"],
        "path_hints": ["webhook", "hook", "callback", "subscribe", "event"],
        "description": "Webhook and event subscription management",
    },
    "analytics": {
        "methods": ["GET"],
        "path_hints": ["analytics", "metrics", "stats", "report", "dashboard", "usage"],
        "description": "Analytics, metrics, and reporting",
    },
    "admin": {
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "path_hints": ["admin", "manage", "config", "setting", "role", "permission"],
        "description": "Administrative and configuration endpoints",
    },
}


def classify_endpoint(endpoint):
    """Classify a single endpoint into capability categories.

    Returns a list of matched capability names.
    """
    method = endpoint.get("method", "").upper()
    path = endpoint.get("path", "").lower()
    summary = (endpoint.get("summary", "") + " " + endpoint.get("description", "")).lower()

    capabilities = []
    for cap_name, rule in CAPABILITY_RULES.items():
        method_match = method in rule["methods"]
        hint_match = any(hint in path or hint in summary for hint in rule["path_hints"])

        # Strong match: method + path hint both match
        if method_match and hint_match:
            capabilities.append(cap_name)

    # Fallback: if no specific capability matched, infer from method alone
    if not capabilities:
        fallback = {
            "GET": "data_retrieval",
            "POST": "creation",
            "PUT": "update",
            "PATCH": "update",
            "DELETE": "deletion",
        }
        if method in fallback:
            capabilities.append(fallback[method])

    return capabilities


def build_recommendations(endpoints):
    """Analyze all endpoints and group them by capability.

    Returns a dict with:
      - capabilities: {cap_name: [list of endpoints]}
      - recommendations: list of {api, capability, reason}
      - summary: human-readable summary string
    """
    cap_groups = {}
    for ep in endpoints:
        caps = classify_endpoint(ep)
        for cap in caps:
            cap_groups.setdefault(cap, []).append(ep)

    recommendations = []
    for cap_name, eps in sorted(cap_groups.items()):
        rule_desc = CAPABILITY_RULES.get(cap_name, {}).get("description", cap_name)
        for ep in eps:
            recommendations.append({
                "api": f"{ep['method']} {ep['path']}",
                "capability": cap_name,
                "capability_description": rule_desc,
                "reason": ep.get("summary") or ep.get("description") or f"Matched by {ep['method']} + path pattern",
                "tags": ep.get("tags", []),
                "parameters": ep.get("parameters", []),
            })

    summary_parts = []
    for cap_name, eps in sorted(cap_groups.items()):
        rule_desc = CAPABILITY_RULES.get(cap_name, {}).get("description", cap_name)
        summary_parts.append(f"  - {cap_name} ({len(eps)} endpoints): {rule_desc}")

    summary = "API Capability Summary:\n" + "\n".join(summary_parts) if summary_parts else "No endpoints found."

    return {
        "capabilities": {k: [f"{e['method']} {e['path']}" for e in v] for k, v in cap_groups.items()},
        "recommendations": recommendations,
        "summary": summary,
        "total_endpoints": len(endpoints),
        "total_capabilities": len(cap_groups),
    }


# ---------------------------------------------------------------------------
# LLM-enhanced analysis (optional, requires ANTHROPIC_API_KEY)
# ---------------------------------------------------------------------------

def _llm_analyze(endpoints_json, use_case=""):
    """Use Claude to provide deeper analysis. Returns a string."""
    try:
        import anthropic
    except ImportError:
        return None

    import os
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None

    client = anthropic.Anthropic(api_key=api_key)

    prompt = f"""You are an API integration expert. Given these API endpoints, provide:
1. A prioritized list of which APIs to integrate first and why.
2. The key capabilities each endpoint provides.
3. Suggested integration flow (what order to call them for a typical workflow).

{"User's use case: " + use_case if use_case else ""}

Endpoints:
{endpoints_json}

Respond in clear, structured markdown."""

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}],
    )

    return message.content[0].text


# ---------------------------------------------------------------------------
# Main Agent class
# ---------------------------------------------------------------------------

class APIRecommendationAgent:
    """Agent that ingests API docs and produces integration recommendations.

    Usage:
        agent = APIRecommendationAgent()
        result = agent.analyze("path/to/openapi.yaml")
        print(result["summary"])
        print(json.dumps(result["recommendations"], indent=2))
    """

    def __init__(self, use_llm=False):
        """
        Args:
            use_llm: If True, attempt to use Claude for deeper analysis.
                     Requires ANTHROPIC_API_KEY env var and anthropic package.
        """
        self.use_llm = use_llm
        self.parser = APIDocParser()

    def analyze(self, source, use_case=""):
        """Analyze API documentation and return recommendations.

        Args:
            source: File path (.json/.yaml/.yml), raw text, or dict of an API spec.
            use_case: Optional description of what the user wants to build.

        Returns:
            Dict with keys: capabilities, recommendations, summary,
            total_endpoints, total_capabilities, and optionally llm_analysis.
        """
        endpoints = self.parser.parse(source)

        if not endpoints:
            return {
                "capabilities": {},
                "recommendations": [],
                "summary": "No API endpoints found in the provided documentation.",
                "total_endpoints": 0,
                "total_capabilities": 0,
            }

        result = build_recommendations(endpoints)

        if self.use_llm:
            trimmed = json.dumps(
                [{"method": e["method"], "path": e["path"],
                  "summary": e.get("summary", "")} for e in endpoints],
                indent=2,
            )
            llm_result = _llm_analyze(trimmed, use_case)
            if llm_result:
                result["llm_analysis"] = llm_result

        return result

    def analyze_and_print(self, source, use_case=""):
        """Convenience method: analyze and print human-readable output."""
        result = self.analyze(source, use_case)

        print("=" * 60)
        print(result["summary"])
        print(f"\nTotal endpoints: {result['total_endpoints']}")
        print(f"Capability categories: {result['total_capabilities']}")
        print("=" * 60)

        print("\nRecommended APIs by capability:\n")
        current_cap = None
        for rec in result["recommendations"]:
            if rec["capability"] != current_cap:
                current_cap = rec["capability"]
                print(f"[{current_cap.upper()}] - {rec['capability_description']}")
            print(f"    {rec['api']}")
            if rec["reason"]:
                print(f"      -> {rec['reason']}")

        if result.get("llm_analysis"):
            print("\n" + "=" * 60)
            print("LLM-Enhanced Analysis:\n")
            print(result["llm_analysis"])

        return result
