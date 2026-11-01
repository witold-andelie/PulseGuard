"""Offline budget decisions and Pub/Sub delivery handling."""

import base64
import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from deploy.gcp.budget_guard.guard import disable_billing, handle_event, should_disable

BUDGET = "PulseGuard trial 300 USD"


def payload(**changes):
    return {"budgetDisplayName": BUDGET, "currencyCode": "USD", "costAmount": 300,
            "budgetAmount": 300, **changes}


def event(value):
    return SimpleNamespace(data={"message": {
        "data": base64.b64encode(json.dumps(value).encode()).decode()
    }})


@pytest.mark.parametrize("cost,expected", [(0, False), (150, False), (270, False),
                                         ("299.999", False), (300, True), ("300.01", True)])
def test_actual_spend_threshold(cost, expected):
    assert should_disable(payload(costAmount=cost), budget_name=BUDGET) is expected


@pytest.mark.parametrize("changes", [
    {"costAmount": "NaN"}, {"costAmount": "Infinity"}, {"costAmount": "bad"},
    {"costAmount": None}, {"costAmount": True}, {"budgetAmount": 0}, {"budgetAmount": -1},
    {"budgetAmount": "NaN"}, {"currencyCode": "EUR"}, {"budgetDisplayName": "Another budget"},
    {"costAmount": 270, "forecastThresholdExceeded": 1.5},
])
def test_ignores_invalid_unrelated_and_forecast_only_messages(changes):
    assert not should_disable(payload(**changes), budget_name=BUDGET)


def test_configured_currency_is_required():
    eur = payload(currencyCode="EUR", costAmount=255, budgetAmount=255)
    assert should_disable(eur, budget_name=BUDGET, currency="EUR")
    assert not should_disable(eur, budget_name=BUDGET)
    assert not should_disable(payload(), budget_name=BUDGET, currency="EUR")


def test_missing_amount_does_not_disable():
    assert not should_disable({"budgetDisplayName": BUDGET, "currencyCode": "USD"},
                              budget_name=BUDGET)


def test_cloud_event_targets_only_configured_project():
    disable = Mock()
    assert handle_event(event(payload(projectId="untrusted-other-project")),
                        project_id="owner-project", budget_name=BUDGET, disable=disable)
    disable.assert_called_once_with("owner-project")


@pytest.mark.parametrize("value", [[], None, "garbage", {"costAmount": 300}])
def test_unusable_payload_acknowledged_without_network(value):
    disable = Mock()
    assert not handle_event(event(value), project_id="p", budget_name=BUDGET, disable=disable)
    disable.assert_not_called()


@pytest.mark.parametrize("data", [{}, {"message": {}}, {"message": {"data": "@@@"}},
                                  {"message": {"data": "eA=="}}])
def test_malformed_delivery_is_ignored(data):
    disable = Mock()
    assert not handle_event(SimpleNamespace(data=data), project_id="p", budget_name=BUDGET,
                            disable=disable)
    disable.assert_not_called()


def test_api_failure_is_retried_by_platform():
    disable = Mock(side_effect=RuntimeError("transient API error"))
    with pytest.raises(RuntimeError, match="transient"):
        handle_event(event(payload()), project_id="p", budget_name=BUDGET, disable=disable)


@pytest.mark.parametrize("enabled", [False, True])
def test_sdk_adapter_is_idempotent_and_sends_empty_billing_account(monkeypatch, enabled):
    client = Mock()
    client.get_project_billing_info.return_value.billing_enabled = enabled
    module = SimpleNamespace(CloudBillingClient=lambda: client, ProjectBillingInfo=SimpleNamespace)
    monkeypatch.setitem(sys.modules, "google.cloud.billing_v1", module)
    disable_billing("owner-project")
    client.get_project_billing_info.assert_called_once_with(name="projects/owner-project")
    if enabled:
        args = client.update_project_billing_info.call_args.kwargs
        assert args["name"] == "projects/owner-project"
        assert args["project_billing_info"].billing_account_name == ""
    else:
        client.update_project_billing_info.assert_not_called()
