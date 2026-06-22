import json
from unittest.mock import patch, MagicMock

import pytest
import requests

from simulators.cisco_router import CiscoRouterSimulator, CiscoRouterMetrics


# fixture providing a fresh cisco simulator for each test
@pytest.fixture
def sim():
    return CiscoRouterSimulator(hostname="router-1", collector_url="http://localhost:8000/metrics")


# initializing the simulator sets all attributes to expected defaults
def test_init_sets_attributes(sim):

    assert sim.hostname == "router-1"
    assert sim.collector_url == "http://localhost:8000/metrics"
    assert sim.netflow_host == "127.0.0.1"
    assert sim.netflow_port == 2055
    assert sim.running is False
    assert sim.thread is None
    assert sim.netflow_socket is None


# start launches a background daemon thread and creates the udp socket
@patch("simulators.cisco_router.requests.post")
def test_start_launches_thread(mock_post, sim):

    sim.start()
    try:
        assert sim.running is True
        assert sim.thread is not None
        assert sim.thread.is_alive()
        assert sim.netflow_socket is not None
    finally:
        sim.stop()


# stop joins the background thread and resets all resources
@patch("simulators.cisco_router.requests.post")
def test_stop_joins_thread(mock_post, sim):

    sim.start()
    sim.stop()
    assert sim.running is False
    assert sim.thread is None
    assert sim.netflow_socket is None


# export_metrics builds a cisco payload and posts it to the collector
@patch("simulators.cisco_router.requests.post")
def test_export_metrics_posts_payload(mock_post, sim):

    sim.export_metrics()

    assert mock_post.called
    payload = mock_post.call_args.kwargs["json"]
    assert payload["hostname"] == "router-1"
    assert payload["vendor"] == "cisco"
    assert 0.0 <= payload["cpu"] <= 100.0
    assert 0.0 <= payload["memory"] <= 100.0
    assert "interface_stats" in payload
    assert "ospf_neighbors" in payload
    assert "bgp_peers" in payload


# export_netflow sends a json-encoded flow record via udp
def test_export_netflow_sends_udp(sim):

    # simulate post-start state by injecting a mock socket
    mock_socket = MagicMock()
    sim.netflow_socket = mock_socket
    sim.export_netflow()

    assert mock_socket.sendto.called
    payload_bytes, addr = mock_socket.sendto.call_args[0]
    record = json.loads(payload_bytes.decode("utf-8"))
    assert record["hostname"] == "router-1"
    assert addr == ("127.0.0.1", 2055)


# calling start twice does not spawn a second thread
@patch("simulators.cisco_router.requests.post")
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
@patch("simulators.cisco_router.requests.post", side_effect=requests.RequestException("boom"))
def test_export_metrics_handles_request_failure(mock_post, sim):

    sim.export_metrics()


# export_netflow exits early when the udp socket has not been created
def test_export_netflow_without_socket(sim):

    sim.export_netflow()
    assert sim.netflow_socket is None
