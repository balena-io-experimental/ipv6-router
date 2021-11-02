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

EXAMPLE_IPV6_1="2001:db8:1::"
EXAMPLE_IPV6_PREFIX_1="2001:db8:1::/64"
EXAMPLE_IPV6_PREFIX_2="2001:db8:2::/64"
EXAMPLE_IPV4_PREFIX_1="203.0.113.1"
EXAMPLE_IPV4_PREFIX_2="192.0.2.1"

# Device's physical interface on the local network (eth0=ethernet, wlan0=WiFi typically)
ROUTER_INTERFACE="${ROUTER_INTERFACE:-eth0}"
# Tunnel's "routed prefix", to be advertised to the local network
ROUTED_PREFIX="${ROUTED_PREFIX:-"${EXAMPLE_IPV6_PREFIX_1}"}"
TUNNEL_PREFIX="${TUNNEL_PREFIX:-"${EXAMPLE_IPV6_PREFIX_2}"}"
ROUTED_PREFIX_LEN="${ROUTED_PREFIX/*::\//}" # e.g. '64' in 'a:b::/64'
TUNNEL_PREFIX_LEN="${TUNNEL_PREFIX/*::\//}" # e.g. '64' in 'a:b::/64'

# Tunnel's own subnet, from which ::1 (gateway) and ::2 (client) are derived
TUNNEL_REMOTE_GW="${TUNNEL_PREFIX/::\/*/::1}"
TUNNEL_LOCAL_IP6="${TUNNEL_PREFIX/::\//::2\/}"
# Tunnel's public IPv4, remote endpoint (Hurricane Electric)
TUNNEL_REMOTE_IP4="${TUNNEL_REMOTE_IP4:-"${EXAMPLE_IPV4_PREFIX_1}"}"
# Device's private IPv4 address on the local network
TUNNEL_LOCAL_IP4="${TUNNEL_LOCAL_IP4:-"${EXAMPLE_IPV4_PREFIX_2}"}"
# Client whitelists: lists of clients to be served with router advertisements
# and/or DHCPv6 address leases
# Semicolon separated list of client 'fe80::' IPv6 addresses to advertise to
CLIENTS_WHITELIST="${CLIENTS_WHITELIST:-"${EXAMPLE_IPV6_1}";}"
# Semicolon separated list of client MAC addresses to serve DHCPv6 to
CLIENTS_WHITELIST_MAC="${CLIENTS_WHITELIST_MAC:-}"
# Address used for ping to determine MTU size.
IPV4_TEST_MTU_ADDR="${IPV4_TEST_MTU_ADDR:-"${TUNNEL_REMOTE_IP4}"}"

# MTU depends on the IPv4 ISP, e.g. TUNNEL_MTU='1472' for Vodafone UK home broadband.
# The MTU also needs to be configured in the Hurricane Electric web interface.
# Based on the firmware script at
# https://www.routertech.org/viewtopic.php?t=1720
function set_tunnel_mtu {
	ATT="50"
	CURR_MTU="500"
	DIFF="1000"
	TUNNEL_MTU="0"
	echo "Determining MTU..."
	while [ "$ATT" -gt "0" ]
	do
			DIFF=`expr "$DIFF" / 2 + "$DIFF" % 2`
			ping -I "${ROUTER_INTERFACE}" -c 1 -M do -s "${CURR_MTU}" ${IPV4_TEST_MTU_ADDR} > /dev/null 2>&1
			if [ "$?" -eq 0 ]; then
					if [ "$TUNNEL_MTU" -eq "$CURR_MTU" ]; then
							break;
					else
							TUNNEL_MTU="$CURR_MTU"
							CURR_MTU=`expr "$CURR_MTU" + "$DIFF"`
					fi
			else
					CURR_MTU=`expr "$CURR_MTU" - "$DIFF"`
			fi
			ATT=`expr "$ATT" - 1`
	done
	if [ "$ATT" -eq "0" ] || [ "$CURR_MTU" -le "0" ]; then
		echo "Could not determine MTU, using default value 1480"
		TUNNEL_MTU="1480"
	else
		# Add 8 bytes for the ICMP header. The 20 bytes of the IPv4 header
		# is not added because it is also present in 6in4 encapsulation.
		TUNNEL_MTU=`expr "$TUNNEL_MTU" + 8`
		echo "Determined MTU: ${TUNNEL_MTU}"
	fi
}

# URL-safe character escaping (https://stackoverflow.com/a/34407620)
function escape {
	printf %s "${1}" | jq -Rrs '@uri'
}

# Print the clients' current public IPv4 address (IPv4 router address)
function get_public_ipv4 {
	# This is similar to the more popular `curl ifconfig.me` command line,
	# however www.opendns.com is arguably a more reputable and performant
	# source, being owned by Cisco and highly geographically distributed.
	dig -4 +short myip.opendns.com @resolver1.opendns.com
}

function prefix_fixup {
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
}

function check_configuration {
	if [ "${ROUTED_PREFIX}" = "${EXAMPLE_IPV6_PREFIX_1}" ] ||
		[ "${TUNNEL_PREFIX}" = "${EXAMPLE_IPV6_PREFIX_2}" ] ||
		[ "${TUNNEL_REMOTE_IP4}" = "${EXAMPLE_IPV4_PREFIX_1}" ] ||
		[ "${TUNNEL_LOCAL_IP4}" = "${EXAMPLE_IPV4_PREFIX_2}" ] ||
		[ "${CLIENTS_WHITELIST}" = "${EXAMPLE_IPV6_1};" ]; then
			echo "Router requires configuration - please replace example values" \
			 " using service variables"
			while true; do sleep 60; done
	fi
}

function watch_external_ip4 {
	if [[ -z "${HE_USERNAME}" || -z "${HE_UPDATE_KEY}" || -z "${HE_TUNNEL_ID}" ]]; then
		echo "[WARN] Environment variables HE_USERNAME, HE_UPDATE_KEY or HE_TUNNEL_ID not defined."
		echo "[WARN] The client's public IPv4 address will not be monitored and notified to tunnelbroker.net."
		return
	fi
	CURRENT_IP="$(get_public_ipv4)"
	echo "Detected client's current public IPv4 address: '${CURRENT_IP}'"
	while true; do
		echo "Notifying client's public IPv4 address to tunnelbroker.net"
		curl -4sSL "https://ipv4.tunnelbroker.net/nic/update?username=$(escape ${HE_USERNAME})&password=$(escape ${HE_UPDATE_KEY})&hostname=$(escape ${HE_TUNNEL_ID})"
		sleep 60
		NEW_IP="$(get_public_ipv4)"
		while [ "${?}" -gt 0 ] || [ -z "${NEW_IP}" ] || [ "${NEW_IP}" = "${CURRENT_IP}" ]; do
			sleep 60
			NEW_IP="$(get_public_ipv4)"
		done
		echo "Client's public IPv4 address has changed: OLD='${CURRENT_IP}' NEW='${NEW_IP}'"
	done
}

function setup_6in4_tunnel {
	watch_external_ip4 &
	sleep 3
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

function create_icmpv6_chain {
	ip6tables -N IPV6-ROUTER-ICMPV6 &>/dev/null
	ip6tables -F IPV6-ROUTER-ICMPV6

	# Trust ourselves
	ip6tables -A IPV6-ROUTER-ICMPV6 -s fe80::/64 -p ipv6-icmp -j ACCEPT
	ip6tables -A IPV6-ROUTER-ICMPV6 -s "${ROUTED_PREFIX}" -p ipv6-icmp -j ACCEPT
	ip6tables -A IPV6-ROUTER-ICMPV6 -s "${TUNNEL_PREFIX}" -p ipv6-icmp -j ACCEPT

	# RFC4890 https://www.rfc-editor.org/rfc/rfc4890#section-4.3.1
	ip6tables -A IPV6-ROUTER-ICMPV6 -p icmpv6 --icmpv6-type destination-unreachable -j ACCEPT
	ip6tables -A IPV6-ROUTER-ICMPV6 -p icmpv6 --icmpv6-type packet-too-big -j ACCEPT
	ip6tables -A IPV6-ROUTER-ICMPV6 -p icmpv6 --icmpv6-type time-exceeded -j ACCEPT
	ip6tables -A IPV6-ROUTER-ICMPV6 -p icmpv6 --icmpv6-type parameter-problem -j ACCEPT
	ip6tables -A IPV6-ROUTER-ICMPV6 -p icmpv6 --icmpv6-type echo-request -j ACCEPT
	ip6tables -A IPV6-ROUTER-ICMPV6 -p icmpv6 --icmpv6-type echo-reply -j ACCEPT

	ip6tables -A IPV6-ROUTER-ICMPV6 -j RETURN
}

function setup_firewall {
	create_icmpv6_chain
	ip6tables -N IPV6-ROUTER-FWD &>/dev/null
	ip6tables -F IPV6-ROUTER-FWD
	ip6tables -A IPV6-ROUTER-FWD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	ip6tables -A IPV6-ROUTER-FWD -s "${ROUTED_PREFIX}" -j ACCEPT
	ip6tables -A IPV6-ROUTER-FWD -j IPV6-ROUTER-ICMPV6
	ip6tables -A IPV6-ROUTER-FWD -j REJECT --reject-with icmp6-adm-prohibited

	iptables  -N IPV6-ROUTER-IN &>/dev/null
	iptables  -F IPV6-ROUTER-IN
	ip6tables -N IPV6-ROUTER-IN &>/dev/null
	ip6tables -F IPV6-ROUTER-IN

	# DHCP whitelist
	IFS=';' read -a macs <<< "${CLIENTS_WHITELIST_MAC}"
	for mac in "${macs[@]}"; do
		ip6tables -A IPV6-ROUTER-IN -p udp --dport 67 -m mac --mac-source "${mac}" -j ACCEPT
	done
	ip6tables -A IPV6-ROUTER-IN -p udp --dport 67 -j REJECT
	iptables  -A IPV6-ROUTER-IN -p udp --dport 67 -j REJECT

	ip6tables -A IPV6-ROUTER-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	ip6tables -A IPV6-ROUTER-IN -j IPV6-ROUTER-ICMPV6
	ip6tables -A IPV6-ROUTER-IN -j REJECT --reject-with icmp6-adm-prohibited

	iptables  -D INPUT   -j IPV6-ROUTER-IN
	iptables  -A INPUT   -j IPV6-ROUTER-IN
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
	check_configuration
	prefix_fixup
	setup_firewall
	configure_dnsmasq
	configure_radvd
	if [ "$TUNNEL_TYPE" = 'he-6in4' ]; then
		if [ -z "${TUNNEL_MTU}" ]; then
			set_tunnel_mtu
		fi
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

function sigterm_handler {
	echo "Terminating..."
	del_6in4_tunnel
	for pidfile in /run/*.pid; do
		kill -TERM "$(cat "${pidfile}")"
	done
}

trap sigterm_handler TERM

if [ "$RUN_MODE" = 'idle' ]; then
	# Idle mode for debugging
	while true; do sleep 60; done
else
	main
fi
