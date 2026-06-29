# thin layer on top of the upstream FRR image: adds python3 for the bgp_scraper sidecar and bash for
# the templated-config startup wrapper. SNMP modules are NOT compiled into the upstream alpine FRR
# at quay.io, so we observe BGP state via "vtysh ... json" from the sidecar instead. that path is
# what real-world ops tooling (saltstack frr module, netbox plugins) uses for FRR anyway
FROM quay.io/frrouting/frr:10.0.1

USER root

RUN apk add --no-cache python3 bash

# the daemons file enables just bgpd (zebra/mgmtd/staticd come with the FRR image regardless)
COPY daemons /etc/frr/daemons

# the config template — placeholders get filled in by start.sh from env vars at container boot
COPY frr.conf.tmpl /etc/frr/frr.conf.tmpl

# sidecar that periodically execs `vtysh -c "show bgp summary json"` and POSTs the parsed result
# to the collector as a normal device metric (vendor=frr-router)
COPY bgp_scraper.py /usr/local/bin/bgp_scraper.py

# wrapper entrypoint: templates the config, starts the scraper, hands off to FRR's docker-start
COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh /usr/local/bin/bgp_scraper.py

ENTRYPOINT ["/usr/local/bin/start.sh"]
