FROM alpine:3.14
RUN apk update && apk add tini bash ip6tables networkmanager radvd
WORKDIR /usr/src/app
COPY radvd.conf /etc/radvd.conf
COPY start.sh /usr/src/app/start.sh

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/usr/src/app/start.sh"]
