# Simulator Test Cases

Documents every pytest case in `python/tests/`. Each entry: test number, function name, category (normal/edge/negative), one-line description, inputs, expected outputs.

Run from `python/` with: `pytest tests/`

---

## Cisco Router (`test_cisco_router.py`)

#1 test_init_sets_attributes (normal)
Initializing the simulator sets all attributes to expected defaults.
inputs: hostname="router-1", collector_url="http://localhost:8000/metrics"
expected outputs: hostname=="router-1", collector_url matches input, netflow_host=="127.0.0.1", netflow_port==2055, running==False, thread is None, netflow_socket is None

#2 test_start_launches_thread (normal)
Calling start() flips running to True, spawns a daemon thread, and creates the UDP socket.
inputs: fresh simulator, requests.post patched
expected outputs: running==True, thread is not None and alive, netflow_socket is not None

#3 test_stop_joins_thread (normal)
Calling stop() after start() flips running to False, joins the thread, and releases resources.
inputs: started simulator, requests.post patched
expected outputs: running==False, thread is None, netflow_socket is None

#4 test_export_metrics_posts_payload (normal)
export_metrics() builds a CiscoRouterMetrics payload and POSTs it to the collector.
inputs: simulator with hostname="router-1", requests.post patched
expected outputs: requests.post called once with json payload containing hostname=="router-1", vendor=="cisco", cpu in [0,100], memory in [0,100], interface_stats / ospf_neighbors / bgp_peers keys present

#5 test_export_netflow_sends_udp (normal)
export_netflow() sends a JSON-encoded flow record over UDP to the configured collector.
inputs: simulator with netflow_socket injected as MagicMock
expected outputs: sendto called once with JSON payload containing hostname=="router-1" and destination address ("127.0.0.1", 2055)

#6 test_double_start_is_idempotent (edge)
Calling start() twice does not spawn a second thread or recreate the socket.
inputs: simulator with start() called twice, requests.post patched
expected outputs: thread reference unchanged after the second start() call

#7 test_stop_before_start_is_safe (edge)
Calling stop() on a fresh simulator is safe and does not raise.
inputs: fresh simulator (start never called)
expected outputs: no exception raised, running stays False, thread stays None

#8 test_export_metrics_handles_request_failure (negative)
export_metrics() catches RequestException without crashing the caller.
inputs: simulator with requests.post patched to raise RequestException
expected outputs: export_metrics() returns normally, no exception propagated

#9 test_export_netflow_without_socket (negative)
export_netflow() exits early when netflow_socket is None (start never called).
inputs: fresh simulator with netflow_socket is None
expected outputs: no exception raised, no UDP send attempted

---

## Juniper SRX (`test_juniper_srx.py`)

#1 test_init_sets_attributes (normal)
Initializing the simulator sets all attributes to expected defaults.
inputs: hostname="srx-1", collector_url="http://localhost:8000/metrics"
expected outputs: hostname=="srx-1", collector_url matches input, running==False, thread is None

#2 test_start_launches_thread (normal)
Calling start() flips running to True and spawns a daemon thread.
inputs: fresh simulator, requests.post patched
expected outputs: running==True, thread is not None and alive

#3 test_stop_joins_thread (normal)
Calling stop() after start() flips running to False and joins the thread.
inputs: started simulator, requests.post patched
expected outputs: running==False, thread is None

#4 test_export_metrics_posts_payload (normal)
export_metrics() builds a JuniperSRXMetrics payload and POSTs it to the collector.
inputs: simulator with hostname="srx-1", requests.post patched
expected outputs: requests.post called once with json payload containing hostname=="srx-1", vendor=="juniper", cpu in [0,100], memory in [0,100], active_sessions in [1000,5000], vpn_status is dict, firewall_throughput > 0

#5 test_vpn_status_structure (normal)
_generate_vpn_status() returns a dict of 3 tunnels with boolean status values.
inputs: simulator instance
expected outputs: dict with keys {tunnel-0, tunnel-1, tunnel-2}, all values are bool

#6 test_double_start_is_idempotent (edge)
Calling start() twice does not spawn a second thread.
inputs: simulator with start() called twice, requests.post patched
expected outputs: thread reference unchanged after the second start() call

#7 test_stop_before_start_is_safe (edge)
Calling stop() on a fresh simulator is safe and does not raise.
inputs: fresh simulator
expected outputs: no exception raised, running stays False, thread stays None

#8 test_export_metrics_handles_request_failure (negative)
export_metrics() catches RequestException without crashing the caller.
inputs: simulator with requests.post patched to raise RequestException
expected outputs: export_metrics() returns normally, no exception propagated

---

## Palo Alto (`test_paloalto.py`)

#1 test_init_sets_attributes (normal)
Initializing the simulator sets all attributes to expected defaults.
inputs: hostname="pa-1", collector_url="http://localhost:8000/metrics"
expected outputs: hostname=="pa-1", collector_url matches input, running==False, thread is None

#2 test_start_launches_thread (normal)
Calling start() flips running to True and spawns a daemon thread.
inputs: fresh simulator, requests.post patched
expected outputs: running==True, thread is not None and alive

#3 test_stop_joins_thread (normal)
Calling stop() after start() flips running to False and joins the thread.
inputs: started simulator, requests.post patched
expected outputs: running==False, thread is None

#4 test_export_metrics_posts_payload (normal)
export_metrics() builds a PaloAltoMetrics payload and POSTs it to the collector.
inputs: simulator with hostname="pa-1", requests.post patched
expected outputs: requests.post called once with json payload containing hostname=="pa-1", vendor=="paloalto", ips_alerts in [0,50], blocked_connections in [0,200], url_filtering_stats is dict, security_events is list

#5 test_url_filtering_categories (normal)
_generate_url_filtering_stats() returns hit counts for the 6 expected URL categories.
inputs: simulator instance
expected outputs: dict with keys {social-media, streaming, malware, phishing, business, news}, all values are int

#6 test_security_events_structure (normal)
_generate_security_events() returns 0 to 3 events, each with type, severity, src_ip, timestamp.
inputs: simulator instance
expected outputs: list of length in [0,3], each entry contains the four required keys

#7 test_double_start_is_idempotent (edge)
Calling start() twice does not spawn a second thread.
inputs: simulator with start() called twice, requests.post patched
expected outputs: thread reference unchanged after the second start() call

#8 test_stop_before_start_is_safe (edge)
Calling stop() on a fresh simulator is safe and does not raise.
inputs: fresh simulator
expected outputs: no exception raised, running stays False, thread stays None

#9 test_export_metrics_handles_request_failure (negative)
export_metrics() catches RequestException without crashing the caller.
inputs: simulator with requests.post patched to raise RequestException
expected outputs: export_metrics() returns normally, no exception propagated
