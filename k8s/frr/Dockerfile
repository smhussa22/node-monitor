# thin layer on top of the upstream FRR image: just adds python3 so the bgp_scraper sidecar can run
# alongside bgpd. we deliberately skip net-snmp / agentx wiring because the upstream alpine FRR build
# at quay.io/frrouting/frr does not ship bgpd_snmp.so — we'd need a from-source build to get it. the
# scraper polls vtysh locally instead, which is what real-world ops tooling does for FRR anyway
FROM quay.io/frrouting/frr:10.0.1

USER root

RUN apk add --no-cache python3 bash

COPY daemons /etc/frr/daemons
COPY bgp_scraper.py /usr/local/bin/bgp_scraper.py
COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh /usr/local/bin/bgp_scraper.py

ENTRYPOINT ["/usr/local/bin/start.sh"]
