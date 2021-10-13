#!/bin/bash

# TUNNEL_TYPE - Allowed values are:
# * 'he-6in4' - Hurricane Electric's https://tunnelbroker.net/ 6in4 tunnel, two /64 prefixes
# * '6project-openvpn' - https://6project.org/ OpenVPN-based tunnel, single /80 prefix
TUNNEL_TYPE="${TUNNEL_TYPE:-he-6in4}"

if [ "${TUNNEL_TYPE}" = 'he-6in4' ]; then
	TUNNEL_INTERFACE='he-6in4'
elif [ "${TUNNEL_TYPE}" = '6project-openvpn' ]; then
	TUNNEL_INTERFACE='tun0' # note: this name cannot be changed just here
fi

# Device's physical interface on the local network (eth0=ethernet, wlan0=WiFi typically)
ROUTER_INTERFACE="${ROUTER_INTERFACE:-eth0}"
# Tunnel's "routed prefix", to be advertised to the local network
ROUTED_PREFIX="${ROUTED_PREFIX:-2001:db8:1::/64}"
TUNNEL_PREFIX="${TUNNEL_PREFIX:-2001:db8:2::/64}"
ROUTED_PREFIX_LEN="${ROUTED_PREFIX/*::\//}" # e.g. '64' in 'a:b::/64'
TUNNEL_PREFIX_LEN="${TUNNEL_PREFIX/*::\//}" # e.g. '64' in 'a:b::/64'

# Tunnel's own subnet, from which ::1 (gateway) and ::2 (client) are derived
TUNNEL_REMOTE_GW="${TUNNEL_PREFIX/::\/*/::1}"
TUNNEL_LOCAL_IP6="${TUNNEL_PREFIX/::\//::2\/}"
# Tunnel's public IPv4, remote endpoint (Hurricane Electric)
TUNNEL_REMOTE_IP4="${TUNNEL_REMOTE_IP4:-203.0.113.1}"
# Device's private IPv4 address on the local network
TUNNEL_LOCAL_IP4="${TUNNEL_LOCAL_IP4:-192.0.2.1}"
# Client whitelists: lists of clients to be served with router advertisements
# and/or DHCPv6 address leases
# Semicolon separated list of client 'fe80::' IPv6 addresses to advertise to
CLIENTS_WHITELIST="${CLIENTS_WHITELIST:-2001:db8:1::;}"
# Semicolon separated list of client MAC addresses to serve DHCPv6 to
CLIENTS_WHITELIST_MAC="${CLIENTS_WHITELIST_MAC:-}"

# MTU depends on the IPv4 ISP, e.g. '1472' for Vodafone UK. ToDo: Implement auto detection.
# The MTU also needs to be configured in the Hurricane Electric web interface.
TUNNEL_MTU=${TUNNEL_MTU:-1480}

ORIGINAL_TUNNEL_PREFIX="${TUNNEL_PREFIX}"
ORIGINAL_ROUTED_PREFIX="${ROUTED_PREFIX}"

# If TUNNEL_PREFIX is the same as ROUTED_PREFIX (e.g. single 6project.org /80),
# then split in two by adding 1 to the prefix length, e.g.:
# - Tunnel Prefix changes from a:b:c::/80 to a:b:c::/81
# - Routed Prefix changes from a:b:c::/80 to a:b:c:8000::/81
if [ "${ROUTED_PREFIX}" = "${TUNNEL_PREFIX}" ]; then
	ROUTED_PREFIX_LEN=$((ROUTED_PREFIX_LEN + 1))
	TUNNEL_PREFIX_LEN="${ROUTED_PREFIX_LEN}"
	ROUTED_PREFIX="${ROUTED_PREFIX/::\/*/:8000::}/${ROUTED_PREFIX_LEN}"
	TUNNEL_PREFIX="${TUNNEL_PREFIX/::\/*/::}/${TUNNEL_PREFIX_LEN}"
fi

function setup_6in4_tunnel {
	DBUS_SYSTEM_BUS_ADDRESS=unix:path=/host/run/dbus/system_bus_socket \
		nmcli connection add \
			con-name "${TUNNEL_INTERFACE}" ifname "${TUNNEL_INTERFACE}" \
			type ip-tunnel mode sit mtu "${TUNNEL_MTU}" \
			remote "${TUNNEL_REMOTE_IP4}" local "${TUNNEL_LOCAL_IP4}" -- \
			ipv4.method disabled ipv6.method manual \
			ipv6.gateway "${TUNNEL_REMOTE_GW}" \
			ipv6.address "${TUNNEL_LOCAL_IP6}"

	# The nmcli command above is not respecting the mtu parameter - why? -
	# hence adding this `ip link set` workaround. Can we make NetworkManager
	# respect it through some config file or another `nmcli` command?
	# `nmcli dev modify he-sit mtu 1472` did not work either, why not?
	sleep 3
	ip link set "${TUNNEL_INTERFACE}" mtu "${TUNNEL_MTU}"
}

function del_6in4_tunnel {
	DBUS_SYSTEM_BUS_ADDRESS=unix:path=/host/run/dbus/system_bus_socket \
		nmcli connection del "${TUNNEL_INTERFACE}" > /dev/null 2>&1
}

function setup_routing {
	ip -6 addr add "${ROUTED_PREFIX/::\//::1\/}" dev "${ROUTER_INTERFACE}"
	sysctl net.ipv6.conf.all.forwarding=1
}

function fix_tunnel_address {
	if [ "${ORIGINAL_TUNNEL_PREFIX}" = "${ORIGINAL_ROUTED_PREFIX}" ]; then
		ip -6 addr del "${ORIGINAL_TUNNEL_PREFIX/::\//::2\/}" dev "${TUNNEL_INTERFACE}"
		ip -6 addr add "${TUNNEL_PREFIX/::\//::2\/}" dev "${TUNNEL_INTERFACE}"
	fi
}

function setup_firewall {
	ip6tables -N IPV6-ROUTER-FWD
	ip6tables -F IPV6-ROUTER-FWD
	ip6tables -A IPV6-ROUTER-FWD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	ip6tables -A IPV6-ROUTER-FWD -s "${ROUTED_PREFIX}" -j ACCEPT
	ip6tables -A IPV6-ROUTER-FWD -j REJECT --reject-with icmp6-adm-prohibited

	ip6tables -N IPV6-ROUTER-IN
	ip6tables -F IPV6-ROUTER-IN

	ORIGINAL_IFS="${IFS}"
	IFS=';'
	for mac in ${CLIENTS_WHITELIST_MAC}; do
		iptables  -A IPV6-ROUTER-IN -p udp --dport 67 -m mac --mac-source "${mac}" -j ACCEPT
		ip6tables -A IPV6-ROUTER-IN -p udp --dport 67 -m mac --mac-source "${mac}" -j ACCEPT
	done
	IFS="${ORIGINAL_IFS}"
	ip6tables -A IPV6-ROUTER-IN -p udp --dport 67 -j REJECT

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

function configure_dnsmasq {
	cat << EOF > "/etc/dnsmasq.conf"
port=0
interface=${ROUTER_INTERFACE}
dhcp-range=${ROUTED_PREFIX/::\/*/::10},${ROUTED_PREFIX/::\/*/::fff},${ROUTED_PREFIX_LEN}
EOF
}

function configure_radvd {
	if [ "${CLIENTS_WHITELIST: -1}" != ';' ]; then
		CLIENTS_WHITELIST="${CLIENTS_WHITELIST};"
	fi
	CLIENTS_WHITELIST=$(echo "${CLIENTS_WHITELIST}" | sed 's/;/;\n\t\t/g')
	if [ "${ROUTED_PREFIX_LEN}" = '64' ]; then
		MANAGED_FLAG='off' # Do not require DHCPv6, use SLAAC
	else
		MANAGED_FLAG='on'  # Require DHCPv6
	fi
	cat << EOF > "/etc/radvd.conf"
interface ${ROUTER_INTERFACE} {
	AdvSendAdvert on;
	AdvManagedFlag ${MANAGED_FLAG};
	AdvOtherConfigFlag off;
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
		sleep 20
		RADVD_PID=$(cat "$PID_FILE")
		while kill -s 0 "$RADVD_PID" &>/dev/null; do
			sleep 10
		done
	done
}

function start_openvpn {
	local PID_FILE='/run/openvpn.pid'
	local PID_NUM
	while true; do
		rm -f "$PID_FILE"
		openvpn --writepid "$PID_FILE" --log-append '/data/openvpn.log' /etc/openvpn/client.conf &

		sleep 5
		fix_tunnel_address

		PID_NUM=$(cat "$PID_FILE")
		while kill -s 0 "$PID_NUM" &>/dev/null; do
			sleep 10
		done
	done
}

function start_dnsmasq {
	local PID_FILE='/run/dnsmasq.pid'
	local PID_NUM
	while true; do
		rm -f "$PID_FILE"
		dnsmasq --pid-file="$PID_FILE" --log-facility='/data/dnsmasq.log' --log-debug -C '/etc/dnsmasq.conf'
		sleep 5
		PID_NUM=$(cat "$PID_FILE")
		while kill -s 0 "$PID_NUM" &>/dev/null; do
			sleep 10
		done
	done
}

function main {
	setup_firewall
	configure_dnsmasq
	configure_radvd
	if [ "$TUNNEL_TYPE" = 'he-6in4' ]; then
		del_6in4_tunnel
		setup_6in4_tunnel
	fi
	if [ "$TUNNEL_TYPE" = '6project-openvpn' ]; then
		start_openvpn &
		start_dnsmasq &
	fi
	setup_routing
	start_radvd # here the script blocks in a loop
}

if [ "$RUN_MODE" = 'idle' ]; then
	# Idle mode for debugging
	while true; do sleep 60; done
else
	main
fi
