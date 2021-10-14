FROM alpine:3.14
RUN apk update && apk add tini bash ip6tables networkmanager radvd dnsmasq openvpn
WORKDIR /usr/src/app
COPY openvpn-client.conf /etc/openvpn/client.conf
COPY start.sh /usr/src/app/start.sh

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/usr/src/app/start.sh"]
