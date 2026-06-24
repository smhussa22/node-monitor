from unittest.mock import patch

import pytest
import requests

from simulators.juniper_srx import JuniperSRXSimulator, JuniperSRXMetrics


# fixture providing a fresh juniper srx simulator for each test
@pytest.fixture
def sim():
    return JuniperSRXSimulator(hostname="srx-1", collector_url="http://localhost:8000/metrics")


# initializing the simulator sets all attributes to expected defaults
def test_init_sets_attributes(sim):

    assert sim.hostname == "srx-1"
    assert sim.collector_url == "http://localhost:8000/metrics"
    assert sim.running is False
    assert sim.thread is None


# start launches a background daemon thread
@patch("simulators.juniper_srx.requests.post")
def test_start_launches_thread(mock_post, sim):

    sim.start()
    try:
        assert sim.running is True
        assert sim.thread is not None
        assert sim.thread.is_alive()
    finally:
        sim.stop()


# stop joins the background thread and resets state
@patch("simulators.juniper_srx.requests.post")
def test_stop_joins_thread(mock_post, sim):

    sim.start()
    sim.stop()
    assert sim.running is False
    assert sim.thread is None


# export_metrics builds a juniper payload and posts it to the collector
@patch("simulators.juniper_srx.requests.post")
def test_export_metrics_posts_payload(mock_post, sim):

    sim.export_metrics()

    assert mock_post.called
    payload = mock_post.call_args.kwargs["json"]
    assert payload["hostname"] == "srx-1"
    assert payload["vendor"] == "juniper"
    assert 0.0 <= payload["cpu"] <= 100.0
    assert 0.0 <= payload["memory"] <= 100.0
    assert 1000 <= payload["active_firewall_sessions"] <= 5000
    assert 0 <= payload["vpn_tunnels_up"] <= 5
    assert payload["firewall_throughput"] > 0
    assert payload["health_status"] in {"healthy", "degraded", "down"}
    assert payload["timestamp"] > 0


# calling start twice does not spawn a second thread
@patch("simulators.juniper_srx.requests.post")
def test_double_start_is_idempotent(mock_post, sim):

    sim.start()
    first_thread = sim.thread
    sim.start()
    try:
        assert sim.thread is first_thread
    finally:
        sim.stop()


# calling stop before start is safe and leaves state untouched
def test_stop_before_start_is_safe(sim):

    sim.stop()
    assert sim.running is False
    assert sim.thread is None


# export_metrics swallows request exceptions without crashing the caller
@patch("simulators.juniper_srx.requests.post", side_effect=requests.RequestException("boom"))
def test_export_metrics_handles_request_failure(mock_post, sim):

    sim.export_metrics()
