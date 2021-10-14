FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y tini bash iptables network-manager radvd dnsmasq openvpn
WORKDIR /usr/src/app
COPY openvpn-client.conf /etc/openvpn/client.conf
COPY start.sh /usr/src/app/start.sh

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/src/app/start.sh"]
