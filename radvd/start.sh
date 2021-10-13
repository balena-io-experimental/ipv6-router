#!/bin/bash

# Device's physical interface on the local network (eth0=ethernet, wlan0=WiFi typically)
ROUTER_INTERFACE="${ROUTER_INTERFACE:-eth0}"
# Tunnel's "routed prefix", to be advertised to the local network
ROUTED_PREFIX="${ROUTED_PREFIX:-2001:db8:1::/64}"
TUNNEL_PREFIX="${TUNNEL_PREFIX:-2001:db8:2::/64}"

# Tunnel's own subnet, from which ::1 (gateway) and ::2 (client) are derived
TUNNEL_REMOTE_GW="${TUNNEL_PREFIX/::\/*/::1}"
TUNNEL_LOCAL_IP6="${TUNNEL_PREFIX/::\//::2\/}"
# Tunnel's public IPv4, remote endpoint (Hurricane Electric)
TUNNEL_REMOTE_IP4="${TUNNEL_REMOTE_IP4:-203.0.113.1}"
# Device's private IPv4 address on the local network
TUNNEL_LOCAL_IP4="${TUNNEL_LOCAL_IP4:-192.0.2.1}"
# Semi colon separated list of clients to advertise to
CLIENTS_WHITELIST="${CLIENTS_WHITELIST:-2001:db8:1::;}"

# MTU depends on the IPv4 ISP. Vodafone UK needed 1472. We should implement auto detection.
# The MTU also needs to be configured in the Hurricane Electric web interface.
TUNNEL_MTU=${TUNNEL_MTU:-1480}

function setup_6in4_tunnel {
	DBUS_SYSTEM_BUS_ADDRESS=unix:path=/host/run/dbus/system_bus_socket \
		nmcli connection add \
			con-name he-sit ifname he-sit \
			type ip-tunnel mode sit mtu "${TUNNEL_MTU}" \
			remote "${TUNNEL_REMOTE_IP4}" local "${TUNNEL_LOCAL_IP4}" -- \
			ipv4.method disabled ipv6.method manual \
			ipv6.gateway "${TUNNEL_REMOTE_GW}" \
			ipv6.address "${TUNNEL_LOCAL_IP6}"

	# I found that the nmcli command above was not respecting the mtu parameter (why?),
	# hence adding this unreliable `ip link set` workaround. Can we make NetworkManager
	# respect it through some config file or another `nmcli` command?
	# `nmcli dev modify he-sit mtu 1472` did not work either, why not? Needs down/up?
	sleep 2 && ip link set he-sit mtu "${TUNNEL_MTU}"
}

function del_6in4_tunnel {
	DBUS_SYSTEM_BUS_ADDRESS=unix:path=/host/run/dbus/system_bus_socket \
		nmcli connection del he-sit > /dev/null 2>&1
}

function setup_routing {
	ip -6 addr add "${ROUTED_PREFIX/::\//::1\/}" dev "${ROUTER_INTERFACE}"
	sysctl net.ipv6.conf.all.forwarding=1
}

function setup_firewall {
	ip6tables -N IPV6-ROUTER-FWD
	ip6tables -F IPV6-ROUTER-FWD
	ip6tables -A IPV6-ROUTER-FWD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	ip6tables -A IPV6-ROUTER-FWD -s "${ROUTED_PREFIX}" -j ACCEPT
	ip6tables -A IPV6-ROUTER-FWD -j REJECT --reject-with icmp6-adm-prohibited

	ip6tables -N IPV6-ROUTER-IN
	ip6tables -F IPV6-ROUTER-IN
	ip6tables -A IPV6-ROUTER-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	ip6tables -A IPV6-ROUTER-IN -s fe80::/64 -p ipv6-icmp -j ACCEPT
	ip6tables -A IPV6-ROUTER-IN -s "${ROUTED_PREFIX}" -p ipv6-icmp -j ACCEPT
	ip6tables -A IPV6-ROUTER-IN -s "${TUNNEL_PREFIX}" -p ipv6-icmp -j ACCEPT
	ip6tables -A IPV6-ROUTER-IN -j REJECT --reject-with icmp6-adm-prohibited

	ip6tables -D INPUT   -j IPV6-ROUTER-IN
	ip6tables -A INPUT   -j IPV6-ROUTER-IN
	ip6tables -D FORWARD -j IPV6-ROUTER-FWD
	ip6tables -A FORWARD -j IPV6-ROUTER-FWD
}

function configure_radvd {
	if [ "${CLIENTS_WHITELIST: -1}" != ';' ]; then
		CLIENTS_WHITELIST="${CLIENTS_WHITELIST};"
	fi
	CLIENTS_WHITELIST=$(echo "${CLIENTS_WHITELIST}" | sed 's/;/;\n\t\t/g')
	cat << EOF > "/etc/radvd.conf"
interface ${ROUTER_INTERFACE} {
	AdvSendAdvert on;
	MinRtrAdvInterval 30;
	MaxRtrAdvInterval 90;
	prefix ${ROUTED_PREFIX} {
		AdvOnLink on;
		AdvAutonomous on;
	};
	clients {
		${CLIENTS_WHITELIST}
	};
};
EOF
}

function start_radvd {
	local PID_FILE='/run/radvd.pid'
	local RADVD_PID
	while true; do
		rm -f "$PID_FILE"
		radvd -p "$PID_FILE" -m logfile -l '/data/radvd.log'
		sleep 5
		RADVD_PID=$(cat "$PID_FILE")
		while kill -s 0 "$RADVD_PID" &>/dev/null; do
			sleep 30
		done
	done
}

function main {
	del_6in4_tunnel
	setup_6in4_tunnel
	setup_routing
	setup_firewall
	configure_radvd
	start_radvd
}

main
