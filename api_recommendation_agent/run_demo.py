#!/usr/bin/env python3
"""
Demo: API Recommendation Agent

Shows how to feed API documentation into the agent and get back
structured recommendations for which APIs to use and their capabilities.

Run:
    python -m api_recommendation_agent.run_demo
"""

import json
import sys
import os

# Allow running as a script from the repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api_recommendation_agent import APIRecommendationAgent


# ---------------------------------------------------------------------------
# Sample OpenAPI spec (subset of a fictional e-commerce API)
# ---------------------------------------------------------------------------

SAMPLE_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "ShopFlow API", "version": "1.0.0"},
    "paths": {
        "/auth/login": {
            "post": {
                "summary": "Authenticate user and get access token",
                "tags": ["auth"],
                "parameters": [],
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {}},
                },
            }
        },
        "/auth/register": {
            "post": {
                "summary": "Register a new user account",
                "tags": ["auth"],
            }
        },
        "/products": {
            "get": {
                "summary": "List all products with optional filters",
                "tags": ["products"],
                "parameters": [
                    {"name": "category", "in": "query", "required": False,
                     "description": "Filter by category"},
                    {"name": "search", "in": "query", "required": False,
                     "description": "Full-text search query"},
                ],
            }
        },
        "/products/{id}": {
            "get": {
                "summary": "Get product details by ID",
                "tags": ["products"],
                "parameters": [
                    {"name": "id", "in": "path", "required": True,
                     "description": "Product ID"},
                ],
            }
        },
        "/products/search": {
            "get": {
                "summary": "Search products by keyword with advanced filters",
                "tags": ["products", "search"],
                "parameters": [
                    {"name": "q", "in": "query", "required": True,
                     "description": "Search keyword"},
                ],
            }
        },
        "/cart": {
            "get": {
                "summary": "Get current user cart",
                "tags": ["cart"],
            },
            "post": {
                "summary": "Add item to cart",
                "tags": ["cart"],
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {}},
                },
            },
        },
        "/cart/{item_id}": {
            "delete": {
                "summary": "Remove item from cart",
                "tags": ["cart"],
            }
        },
        "/orders": {
            "post": {
                "summary": "Create a new order from cart",
                "tags": ["orders"],
            },
            "get": {
                "summary": "List user orders",
                "tags": ["orders"],
            },
        },
        "/orders/{id}": {
            "get": {
                "summary": "Get order details and status",
                "tags": ["orders"],
            }
        },
        "/webhooks": {
            "post": {
                "summary": "Register a webhook for order status updates",
                "tags": ["webhooks"],
            },
            "get": {
                "summary": "List registered webhooks",
                "tags": ["webhooks"],
            },
        },
        "/webhooks/{id}": {
            "delete": {
                "summary": "Delete a webhook subscription",
                "tags": ["webhooks"],
            }
        },
        "/analytics/sales": {
            "get": {
                "summary": "Get sales analytics and revenue metrics",
                "tags": ["analytics"],
            }
        },
        "/admin/users": {
            "get": {
                "summary": "List all users (admin only)",
                "tags": ["admin"],
            }
        },
        "/files/upload": {
            "post": {
                "summary": "Upload product images or documents",
                "tags": ["files"],
                "requestBody": {
                    "required": True,
                    "content": {"multipart/form-data": {}},
                },
            }
        },
    },
}

# ---------------------------------------------------------------------------
# Sample plain-text API doc
# ---------------------------------------------------------------------------

SAMPLE_TEXT_DOC = """
Weather API Documentation

GET /weather/current
  Returns current weather for a location.

GET /weather/forecast
  Returns 7-day forecast for a location.

POST /alerts/subscribe
  Subscribe to severe weather alerts via webhook callback.

GET /weather/history
  Query historical weather data for analytics and reporting.

DELETE /alerts/{id}
  Remove an alert subscription.
"""


def demo_openapi():
    """Demonstrate analysis of an OpenAPI spec."""
    print("\n" + "#" * 60)
    print("# DEMO 1: Analyzing an OpenAPI Spec (e-commerce API)")
    print("#" * 60 + "\n")

    agent = APIRecommendationAgent(use_llm=False)
    result = agent.analyze_and_print(SAMPLE_SPEC)

    # Show raw JSON output (what you'd integrate into your platform)
    print("\n--- Raw JSON (for platform integration) ---\n")
    output = {
        "capabilities": result["capabilities"],
        "total_endpoints": result["total_endpoints"],
        "total_capabilities": result["total_capabilities"],
    }
    print(json.dumps(output, indent=2))


def demo_text():
    """Demonstrate analysis of a plain-text API doc."""
    print("\n\n" + "#" * 60)
    print("# DEMO 2: Analyzing a Plain-Text API Doc (weather API)")
    print("#" * 60 + "\n")

    agent = APIRecommendationAgent(use_llm=False)
    result = agent.analyze_and_print(SAMPLE_TEXT_DOC)


def demo_with_llm():
    """Demonstrate LLM-enhanced analysis (requires ANTHROPIC_API_KEY)."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("\n\n--- Skipping LLM demo (set ANTHROPIC_API_KEY to enable) ---")
        return

    print("\n\n" + "#" * 60)
    print("# DEMO 3: LLM-Enhanced Analysis")
    print("#" * 60 + "\n")

    agent = APIRecommendationAgent(use_llm=True)
    agent.analyze_and_print(
        SAMPLE_SPEC,
        use_case="I'm building a marketplace platform and need to integrate product catalog, checkout, and order tracking.",
    )


if __name__ == "__main__":
    demo_openapi()
    demo_text()
    demo_with_llm()

    print("\n\nDone. Use APIRecommendationAgent in your own code:")
    print('  from api_recommendation_agent import APIRecommendationAgent')
    print('  agent = APIRecommendationAgent()')
    print('  result = agent.analyze("path/to/your/api_spec.yaml")')
    print('  # result["recommendations"] -> list of API recommendations')
    print('  # result["capabilities"]    -> grouped by capability type')
