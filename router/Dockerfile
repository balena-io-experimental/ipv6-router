FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y tini bash iptables network-manager radvd dnsmasq openvpn
RUN update-alternatives --set iptables /usr/sbin/iptables-legacy; \
    update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
WORKDIR /usr/src/app
COPY openvpn-client.conf /etc/openvpn/client.conf
COPY start.sh /usr/src/app/start.sh

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/src/app/start.sh"]
