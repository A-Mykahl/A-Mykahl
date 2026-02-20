"""
Parses API documentation from:
  - OpenAPI/Swagger specs (JSON/YAML files or dicts)
  - Plain text / markdown documentation
  - URLs pointing to API docs (fetches and parses automatically)

Extracts structured endpoint information for the recommendation agent.
"""

import json
import re
import yaml


def fetch_url(url):
    """Fetch content from a URL. Returns (content_string, content_type).

    Handles JSON API specs, YAML specs, and HTML/text documentation pages.
    """
    import urllib.request
    import urllib.error

    req = urllib.request.Request(url, headers={"User-Agent": "APIRecommendationAgent/1.0"})
    resp = urllib.request.urlopen(req, timeout=30)
    content_type = resp.headers.get("Content-Type", "")
    raw = resp.read()

    # Try UTF-8 first, fall back to latin-1
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")

    return text, content_type


def _strip_html(html):
    """Minimal HTML tag stripping for extracting text from doc pages."""
    # Remove script/style blocks
    html = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", html, flags=re.DOTALL | re.IGNORECASE)
    # Replace <br>, <p>, <div>, <li> with newlines
    html = re.sub(r"<(br|p|div|li|tr|h[1-6])[^>]*>", "\n", html, flags=re.IGNORECASE)
    # Strip remaining tags
    html = re.sub(r"<[^>]+>", " ", html)
    # Collapse whitespace
    html = re.sub(r"[ \t]+", " ", html)
    html = re.sub(r"\n{3,}", "\n\n", html)
    return html.strip()


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
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if method.startswith("x-") or method == "parameters" or not isinstance(details, dict):
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
    """Parse a plain-text or markdown API doc into endpoint entries.

    Uses heuristics: lines that look like 'GET /something' or
    'POST https://api.example.com/v1/something' are endpoints.

    Args:
        text: Raw string of API documentation.

    Returns:
        A list of endpoint dicts (same shape as parse_openapi_spec output).
    """
    endpoints = []

    # Match patterns like: GET /path, POST https://host/path, etc.
    pattern = re.compile(
        r"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+"
        r"(https?://[^\s]+|/\S+)",
        re.IGNORECASE,
    )

    lines = text.splitlines()
    for i, line in enumerate(lines):
        match = pattern.search(line)
        if match:
            method = match.group(1).upper()
            raw_path = match.group(2)

            # Normalize full URLs to just the path
            if raw_path.startswith("http"):
                from urllib.parse import urlparse
                parsed = urlparse(raw_path)
                path = parsed.path or "/"
            else:
                path = raw_path

            # Grab the next non-empty, non-endpoint line as description
            desc = ""
            for next_line in lines[i + 1 : i + 5]:
                stripped = next_line.strip()
                if stripped and not pattern.search(stripped):
                    desc = stripped.lstrip("- :")
                    break

            endpoints.append({
                "path": path,
                "method": method,
                "summary": desc[:200],
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


def _is_url(s):
    """Check if a string looks like a URL."""
    return bool(re.match(r"https?://", s.strip()))


def _looks_like_openapi(data):
    """Check if a dict looks like an OpenAPI/Swagger spec."""
    if not isinstance(data, dict):
        return False
    return "paths" in data or "swagger" in data or "openapi" in data


class APIDocParser:
    """Unified parser that auto-detects format: URL, file, JSON/YAML string, or text."""

    @staticmethod
    def parse(source):
        """Parse API docs from a URL, file path, dict, or raw text string.

        Supports:
          - URL (http/https): Fetches the page, auto-detects JSON/YAML spec vs HTML doc
          - File path (.json/.yaml/.yml): Reads and parses as OpenAPI spec
          - Dict: Treated as an OpenAPI spec object
          - Raw string: Tries JSON/YAML parse first, falls back to text heuristics

        Returns a list of endpoint dicts.
        """
        # --- Dict input ---
        if isinstance(source, dict):
            return parse_openapi_spec(source)

        if not isinstance(source, str):
            raise ValueError(f"Unsupported source type: {type(source)}")

        # --- URL input ---
        if _is_url(source):
            return APIDocParser._parse_url(source)

        # --- File path input ---
        if source.endswith((".json", ".yaml", ".yml")):
            return parse_openapi_spec(source)

        # --- Raw string input: try structured formats first ---
        try:
            data = json.loads(source)
            if _looks_like_openapi(data):
                return parse_openapi_spec(data)
        except (json.JSONDecodeError, TypeError):
            pass

        try:
            data = yaml.safe_load(source)
            if _looks_like_openapi(data):
                return parse_openapi_spec(data)
        except (yaml.YAMLError, TypeError):
            pass

        # --- Fall back to plain text heuristic parsing ---
        return parse_text_doc(source)

    @staticmethod
    def _parse_url(url):
        """Fetch a URL and parse the response as API documentation."""
        text, content_type = fetch_url(url)

        # If the response is JSON, try as OpenAPI spec
        if "json" in content_type or text.lstrip().startswith("{"):
            try:
                data = json.loads(text)
                if _looks_like_openapi(data):
                    return parse_openapi_spec(data)
            except (json.JSONDecodeError, TypeError):
                pass

        # If YAML content type or looks like YAML
        if "yaml" in content_type or "yml" in content_type:
            try:
                data = yaml.safe_load(text)
                if _looks_like_openapi(data):
                    return parse_openapi_spec(data)
            except (yaml.YAMLError, TypeError):
                pass

        # HTML documentation page — strip tags and parse as text
        if "<html" in text.lower() or "<body" in text.lower():
            text = _strip_html(text)

        return parse_text_doc(text)
