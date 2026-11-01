"""Budget decisions and project-only billing shutdown; no credentials at import time."""

import base64
import binascii
import json
import logging
from decimal import Decimal, InvalidOperation


def should_disable(payload: dict, *, budget_name: str) -> bool:
    """Accept actual USD spend for this budget, never forecasts or malformed amounts."""
    if payload.get("budgetDisplayName") != budget_name or payload.get("currencyCode") != "USD":
        return False
    try:
        cost = Decimal(str(payload["costAmount"]))
        budget = Decimal(str(payload["budgetAmount"]))
        return cost.is_finite() and budget.is_finite() and budget > 0 and cost >= budget
    except (KeyError, InvalidOperation, ValueError):
        return False


def disable_billing(project_id: str) -> None:
    # Lazy import keeps decision/event tests offline and independent of the Google SDK.
    from google.cloud import billing_v1

    client = billing_v1.CloudBillingClient()
    name = f"projects/{project_id}"
    if client.get_project_billing_info(name=name).billing_enabled:
        client.update_project_billing_info(
            name=name,
            project_billing_info=billing_v1.ProjectBillingInfo(billing_account_name=""),
        )


def handle_event(event, *, project_id: str, budget_name: str, disable=disable_billing) -> bool:
    """Handle a gen2 Pub/Sub CloudEvent; API errors propagate for Eventarc retry."""
    try:
        message = event.data["message"]
        payload = json.loads(base64.b64decode(message["data"], validate=True))
    except (KeyError, TypeError, ValueError, binascii.Error):
        logging.warning("Ignoring malformed budget notification")
        return False
    if not isinstance(payload, dict) or not should_disable(payload, budget_name=budget_name):
        return False
    if not project_id:
        raise ValueError("TARGET_PROJECT_ID is required")
    # Never take the target project from a Pub/Sub payload.
    disable(project_id)
    logging.warning("Budget reached; project billing disabled")
    return True
