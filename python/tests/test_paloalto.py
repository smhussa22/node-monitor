from unittest.mock import patch

import pytest
import requests

from simulators.paloalto import PaloAltoSimulator, PaloAltoMetrics


# fixture providing a fresh palo alto simulator for each test
@pytest.fixture
def sim():
    return PaloAltoSimulator(hostname="pa-1", collector_url="http://localhost:8000/metrics")


# initializing the simulator sets all attributes to expected defaults
def test_init_sets_attributes(sim):

    assert sim.hostname == "pa-1"
    assert sim.collector_url == "http://localhost:8000/metrics"
    assert sim.running is False
    assert sim.thread is None


# start launches a background daemon thread
@patch("simulators.paloalto.requests.post")
def test_start_launches_thread(mock_post, sim):

    sim.start()
    try:
        assert sim.running is True
        assert sim.thread is not None
        assert sim.thread.is_alive()
    finally:
        sim.stop()


# stop joins the background thread and resets state
@patch("simulators.paloalto.requests.post")
def test_stop_joins_thread(mock_post, sim):

    sim.start()
    sim.stop()
    assert sim.running is False
    assert sim.thread is None


# export_metrics builds a paloalto payload and posts it to the collector
@patch("simulators.paloalto.requests.post")
def test_export_metrics_posts_payload(mock_post, sim):

    sim.export_metrics()

    assert mock_post.called
    payload = mock_post.call_args.kwargs["json"]
    assert payload["hostname"] == "pa-1"
    assert payload["vendor"] == "paloalto"
    assert 0 <= payload["ips_alerts"] <= 50
    assert 0 <= payload["blocked_connections"] <= 200
    assert isinstance(payload["url_filtering_stats"], dict)
    assert isinstance(payload["security_events"], list)


# _generate_url_filtering_stats returns hit counts for the 6 expected categories
def test_url_filtering_categories(sim):

    stats = sim._generate_url_filtering_stats()
    expected = {"social-media", "streaming", "malware", "phishing", "business", "news"}
    assert set(stats.keys()) == expected
    assert all(isinstance(v, int) for v in stats.values())


# _generate_security_events returns 0 to 3 events each with required fields
def test_security_events_structure(sim):

    events = sim._generate_security_events()
    assert 0 <= len(events) <= 3
    for event in events:
        assert "type" in event
        assert "severity" in event
        assert "src_ip" in event
        assert "timestamp" in event


# calling start twice does not spawn a second thread
@patch("simulators.paloalto.requests.post")
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
@patch("simulators.paloalto.requests.post", side_effect=requests.RequestException("boom"))
def test_export_metrics_handles_request_failure(mock_post, sim):

    sim.export_metrics()
