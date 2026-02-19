"""
Parses API documentation from OpenAPI/Swagger specs (JSON/YAML) or plain text
and extracts structured endpoint information.
"""

import json
import yaml


def parse_openapi_spec(source):
    """Parse an OpenAPI/Swagger spec from a file path or raw dict.

    Args:
        source: A file path (str ending in .json/.yaml/.yml) or a dict.

    Returns:
        A list of endpoint dicts with keys:
          - path, method, summary, description, parameters, tags
    """
    if isinstance(source, str):
        with open(source, "r") as f:
            if source.endswith((".yaml", ".yml")):
                spec = yaml.safe_load(f)
            else:
                spec = json.load(f)
    elif isinstance(source, dict):
        spec = source
    else:
        raise ValueError("source must be a file path (str) or a dict")

    endpoints = []
    paths = spec.get("paths", {})

    for path, methods in paths.items():
        for method, details in methods.items():
            if method.startswith("x-") or method == "parameters":
                continue
            endpoints.append({
                "path": path,
                "method": method.upper(),
                "summary": details.get("summary", ""),
                "description": details.get("description", ""),
                "parameters": _extract_params(details),
                "tags": details.get("tags", []),
            })

    return endpoints


def parse_text_doc(text):
    """Parse a plain-text or markdown API doc into rough endpoint entries.

    Uses simple heuristics: lines that look like 'GET /something' are endpoints.

    Args:
        text: Raw string of API documentation.

    Returns:
        A list of endpoint dicts (same shape as parse_openapi_spec output).
    """
    import re

    endpoints = []
    http_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    pattern = re.compile(
        r"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/\S+)", re.IGNORECASE
    )

    lines = text.splitlines()
    for i, line in enumerate(lines):
        match = pattern.search(line)
        if match:
            method = match.group(1).upper()
            path = match.group(2)
            # Grab the next non-empty line as a rough description
            desc = ""
            for next_line in lines[i + 1 : i + 4]:
                stripped = next_line.strip()
                if stripped and not pattern.search(stripped):
                    desc = stripped
                    break
            endpoints.append({
                "path": path,
                "method": method,
                "summary": desc[:120],
                "description": desc,
                "parameters": [],
                "tags": [],
            })

    return endpoints


def _extract_params(operation_details):
    """Extract parameter names and locations from an OpenAPI operation."""
    params = []
    for p in operation_details.get("parameters", []):
        params.append({
            "name": p.get("name", ""),
            "in": p.get("in", ""),
            "required": p.get("required", False),
            "description": p.get("description", ""),
        })

    # Also note request body if present
    req_body = operation_details.get("requestBody", {})
    if req_body:
        content_types = list(req_body.get("content", {}).keys())
        params.append({
            "name": "(request body)",
            "in": "body",
            "required": req_body.get("required", False),
            "description": f"Accepts: {', '.join(content_types)}" if content_types else "",
        })

    return params


class APIDocParser:
    """Unified parser that auto-detects format."""

    @staticmethod
    def parse(source):
        """Parse API docs from a file path, dict, or raw text string.

        Returns a list of endpoint dicts.
        """
        if isinstance(source, dict):
            return parse_openapi_spec(source)

        if isinstance(source, str):
            # Check if it's a file path to an OpenAPI spec
            if source.endswith((".json", ".yaml", ".yml")):
                return parse_openapi_spec(source)

            # Try parsing as JSON/YAML string first
            try:
                data = json.loads(source)
                if "paths" in data:
                    return parse_openapi_spec(data)
            except (json.JSONDecodeError, TypeError):
                pass

            try:
                data = yaml.safe_load(source)
                if isinstance(data, dict) and "paths" in data:
                    return parse_openapi_spec(data)
            except (yaml.YAMLError, TypeError):
                pass

            # Fall back to plain text heuristic parsing
            return parse_text_doc(source)

        raise ValueError(f"Unsupported source type: {type(source)}")
