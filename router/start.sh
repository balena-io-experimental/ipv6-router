#!/usr/bin/env bash

# Cause this script to exit immediately (and the container to be restarted
# by the balena supervisor) if any command fails (non-zero exit status).
# https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html
set -e

# TUNNEL_TYPE - Allowed values are:
# * 'he-6in4' - Hurricane Electric's https://tunnelbroker.net/ 6in4 tunnel, two /64 prefixes
# * '6project-openvpn' - https://6project.org/ OpenVPN-based tunnel, single /80 prefix
TUNNEL_TYPE="${TUNNEL_TYPE:-"he-6in4"}"

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
ROUTER_INTERFACE="${ROUTER_INTERFACE:-"eth0"}"
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

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# ~~~~ End of user configurable variables ~~~~
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ORIGINAL_TUNNEL_PREFIX="${TUNNEL_PREFIX}"
ORIGINAL_ROUTED_PREFIX="${ROUTED_PREFIX}"
QUIT_FILE='/usr/src/app/die'

function log {
	IFS=' ' printf '[%(%Y-%m-%dT%H:%M:%SZ)T] %s\n' -1 "$*"
}

# If the parent of a child process dies, the child process is an orphan and
# PPID becomes 1 (the parent becomes the init process). PPID 0 was observed
# when starting processes with 'balena-engine exec'.
function is_orphan {
	(( PPID == 0 || PPID == 1 ))
}

function should_quit {
	[ -e "${QUIT_FILE}" ] || is_orphan
}

function retry {
	local attempts="$1"; shift
	local interval_sec="$1"; shift
	local cmd="$1"; shift
	local args=("$@")
	local status='0'
	set -x
	until "${cmd}" "${args[@]}"; do
		{ status="$?"; set +x; } 2>/dev/null
		echo "'${cmd}' failed with exit code '${status}'. Will retry $(( attempts-1 )) more time(s)." >/dev/stderr
		if (( --attempts == 0 )) || should_quit; then
			break
		fi
		sleep "${interval_sec}"
		set -x
	done
	{ set +x; } 2>/dev/null
	return "${status}"
}

# MTU depends on the IPv4 ISP, e.g. TUNNEL_MTU='1472' for Vodafone UK home broadband.
# The MTU also needs to be configured in the Hurricane Electric web interface.
# Based on the firmware script at
# https://www.routertech.org/viewtopic.php?t=1720
function set_tunnel_mtu {
	local ATT='50'
	local CURR_MTU='500'
	local DIFF='1000'
	TUNNEL_MTU='0'
	log 'Determining MTU...'
	while (( ATT > 0 )); do
		DIFF=$(( DIFF / 2 + DIFF % 2 ))
		set -x +e
		ping -I "${ROUTER_INTERFACE}" -c 1 -M 'do' -s "${CURR_MTU}" "${IPV4_TEST_MTU_ADDR}" &>/dev/null
		{ local status="$?"; set +x -e; } 2>/dev/null
		if (( status == 0 )); then
			if (( TUNNEL_MTU == CURR_MTU )); then
				break;
			else
				TUNNEL_MTU="${CURR_MTU}"
				CURR_MTU=$(( CURR_MTU + DIFF ))
			fi
		else
			CURR_MTU=$(( CURR_MTU - DIFF ))
		fi
		(( ATT-- ))
	done
	if (( ATT == 0 || CURR_MTU <= 0 )); then
		log "Could not determine MTU within '${ATT}' pings to '${IPV4_TEST_MTU_ADDR}'"
		TUNNEL_MTU=''
	else
		# Add 8 bytes for the ICMP header. The 20 bytes of the IPv4 header
		# is not added because it is also present in 6in4 encapsulation.
		TUNNEL_MTU=$(( TUNNEL_MTU + 8 ))
		log "Determined MTU: '${TUNNEL_MTU}'"
	fi
}

function check_6in4_mtu {
	if [ -n "${TUNNEL_MTU}" ]; then
		return
	fi
	while [ -z "${TUNNEL_MTU}" ]; do
		set_tunnel_mtu
		if [ -z "${TUNNEL_MTU}" ]; then
			cat - <<EOF >/dev/stderr
-------------------------------------------------------------------------------
Error: Unable to automatically determine 6in4 tunnel MTU value. Will retry.
You can manually set the tunnel MTU value by performing both of the following
actions:

* Visit your tunnel configuration page at https://tunnelbroker.net/ and set
  set the tunnel MTU field (it could be found under the "Tunnel Details" ->
  "Advanced" tab at the time of this writing).
* Use Balena's CLI or web dashboard to set the TUNNEL_MTU env var.

MTU misconfiguration results in a partially broken internet connection where,
for example, some websites will load normally, others will load partially and
yet others will not load at all, without a clear indication of the reason why.
-------------------------------------------------------------------------------
EOF
			sleep 30
		fi
	done

	if [ "${TUNNEL_MTU}" != '1480' ]; then
		until should_quit; do
			cat - <<EOF >/dev/stderr
-------------------------------------------------------------------------------
Error: MTU value '${TUNNEL_MTU}' detected that does not match Hurricane Electric's
default value of '1480'. Please ensure that both of the following actions are
taken:

* Visit your tunnel configuration page at https://tunnelbroker.net/ and set
  set the tunnel MTU field to '${TUNNEL_MTU}' (it could be found under the
  "Tunnel Details" -> "Advanced" tab at the time of this writing).
* Use Balena's CLI or web dashboard to set the TUNNEL_MTU env var to '${TUNNEL_MTU}'
  (without the quotes).

MTU misconfiguration results in a partially broken internet connection where,
for example, some websites will load normally, others will load partially and
yet others will not load at all, without a clear indication of the reason why.
-------------------------------------------------------------------------------
EOF
			sleep 30
		done
	fi
}

# URL-safe character escaping (https://stackoverflow.com/a/34407620)
function escape {
	printf %s "$1" | jq -Rrs '@uri'
}

# Print the clients' current public IPv4 address (IPv4 router address)
function get_public_ipv4 {
	# This is similar to the more popular `curl ifconfig.me` command line,
	# however www.opendns.com is arguably a more reputable and performant
	# source, being owned by Cisco and highly geographically distributed.
	set -x +e
	dig -4 +short myip.opendns.com @resolver1.opendns.com
	{ set +x -e; } 2>/dev/null
}

function prefix_fixup {
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
			log "Router requires configuration - please replace example values" \
			 " using service variables"
			until should_quit; do sleep 5; done
	fi
}

function watch_external_ip4 {
	if [[ -z "${HE_USERNAME}" || -z "${HE_UPDATE_KEY}" || -z "${HE_TUNNEL_ID}" ]]; then
		log "\
[WARN] Environment variables HE_USERNAME, HE_UPDATE_KEY or HE_TUNNEL_ID not defined.
[WARN] The client's public IPv4 address will not be monitored and notified to tunnelbroker.net."
		return
	fi
	local usr
	local pass
	local host
	local current_ip=''
	local new_ip=''
	local status='1'
	usr="$(escape "${HE_USERNAME}")"
	pass="$(escape "${HE_UPDATE_KEY}")"
	host="$(escape "${HE_TUNNEL_ID}")"
	until should_quit; do
		while [[ "${status}" -gt 0 || -z "${new_ip}" || "${new_ip}" = "${current_ip}" ]]; do
			sleep 60
			if should_quit; then
				break 2
			fi
			new_ip="$(get_public_ipv4)"
			status="$?"
		done
		log "Client's public IPv4 address has changed: OLD='${current_ip}' NEW='${new_ip}'"
		set -x
		if curl -4sSLm 10 "https://ipv4.tunnelbroker.net/nic/update?username=${usr}&password=${pass}&hostname=${host}"; then
			{ set +x; } 2>/dev/null
			current_ip="${new_ip}"
		else
			{ set +x; } 2>/dev/null
			sleep 10
		fi
	done
}

function setup_6in4_tunnel {
	watch_external_ip4 &
	sleep 3
	# 'save no' option: Avoid the tunnel coming back up on reboot before
	# the firewall is setup
	DBUS_SYSTEM_BUS_ADDRESS=unix:path=/host/run/dbus/system_bus_socket \
		retry 5 5 nmcli connection add save no \
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
	retry 5 2 ip link set "${TUNNEL_INTERFACE}" mtu "${TUNNEL_MTU}"
}

function del_6in4_tunnel {
	set +e
	DBUS_SYSTEM_BUS_ADDRESS=unix:path=/host/run/dbus/system_bus_socket \
		nmcli connection del "${TUNNEL_INTERFACE}" &>/dev/null
	set -e
}

function setup_routing {
	local lan_ip6="${ROUTED_PREFIX/::\//::1\/}"
	set -x +e
	ip -6 addr del "${lan_ip6}" dev "${ROUTER_INTERFACE}" &>/dev/null
	ip -6 addr add "${lan_ip6}" dev "${ROUTER_INTERFACE}"
	{ set +x -e; } 2>/dev/null
	sysctl net.ipv6.conf.all.forwarding=1
}

function fix_tunnel_address {
	if [ "${ORIGINAL_TUNNEL_PREFIX}" = "${ORIGINAL_ROUTED_PREFIX}" ]; then
		set -x +e
		ip -6 addr del "${ORIGINAL_TUNNEL_PREFIX/::\//::2\/}" dev "${TUNNEL_INTERFACE}" &>/dev/null
		ip -6 addr add "${TUNNEL_PREFIX/::\//::2\/}" dev "${TUNNEL_INTERFACE}"
		{ set +x -e; } 2>/dev/null
	fi
}

function create_icmpv6_chain {
	ip6tables -N IPV6-ROUTER-ICMPV6 &>/dev/null || true
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
	ip6tables -N IPV6-ROUTER-FWD &>/dev/null || true
	ip6tables -F IPV6-ROUTER-FWD
	ip6tables -A IPV6-ROUTER-FWD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	ip6tables -A IPV6-ROUTER-FWD -s "${ROUTED_PREFIX}" -j ACCEPT
	ip6tables -A IPV6-ROUTER-FWD -j IPV6-ROUTER-ICMPV6
	ip6tables -A IPV6-ROUTER-FWD -j REJECT --reject-with icmp6-adm-prohibited

	iptables  -N IPV6-ROUTER-IN &>/dev/null || true
	iptables  -F IPV6-ROUTER-IN
	ip6tables -N IPV6-ROUTER-IN &>/dev/null || true
	ip6tables -F IPV6-ROUTER-IN

	# DHCP whitelist
	local macs
	local mac
	IFS=';' read -ra macs <<< "${CLIENTS_WHITELIST_MAC}"
	for mac in "${macs[@]}"; do
		ip6tables -A IPV6-ROUTER-IN -p udp --dport 67 -m mac --mac-source "${mac}" -j ACCEPT
	done
	ip6tables -A IPV6-ROUTER-IN -p udp --dport 67 -j REJECT
	iptables  -A IPV6-ROUTER-IN -p udp --dport 67 -j REJECT

	ip6tables -A IPV6-ROUTER-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	ip6tables -A IPV6-ROUTER-IN -j IPV6-ROUTER-ICMPV6
	ip6tables -A IPV6-ROUTER-IN -j REJECT --reject-with icmp6-adm-prohibited

	iptables  -D INPUT   -j IPV6-ROUTER-IN &>/dev/null || true
	iptables  -A INPUT   -j IPV6-ROUTER-IN
	ip6tables -D INPUT   -j IPV6-ROUTER-IN &>/dev/null || true
	ip6tables -A INPUT   -j IPV6-ROUTER-IN
	ip6tables -D FORWARD -j IPV6-ROUTER-FWD &>/dev/null || true
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
	CLIENTS_WHITELIST="${CLIENTS_WHITELIST//';'/$';\n\t\t'}"
	if [ "${ROUTED_PREFIX_LEN}" = '64' ]; then
		local MANAGED_FLAG='off' # Do not require DHCPv6, use SLAAC
	else
		local MANAGED_FLAG='on'  # Require DHCPv6
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

function run_radvd {
	set -x +e
	radvd -p '/run/radvd.pid' -m logfile -l '/data/radvd.log'
	{ set +x -e; } 2>/dev/null
}

function run_openvpn {
	set -x +e
	if openvpn --writepid '/run/openvpn.pid' --log-append '/data/openvpn.log' '/etc/openvpn/client.conf'; then
		{ set +x -e; } 2>/dev/null
		sleep 5
		retry 3 5 fix_tunnel_address
	fi
	{ set +x -e; } 2>/dev/null
}

function run_dnsmasq {
	set -x +e
	dnsmasq --pid-file='/run/dnsmasq.pid' --log-facility='/data/dnsmasq.log' --log-debug -C '/etc/dnsmasq.conf'
	{ set +x -e; } 2>/dev/null
}

function run_service {
	local service_name="$1"
	local pid_file="/run/${service_name}.pid"
	local pid_num
	until should_quit; do
		rm -f "${pid_file}"
		run_"${service_name}" &
		sleep 10
		if [ -f "${pid_file}" ]; then
			# sleep while the service is running
			pid_num="$(cat "${pid_file}")"
			while kill -0 "${pid_num}" &>/dev/null; do
				if should_quit; then
					kill -15 "${pid_num}" &>/dev/null || true
					break
				fi
				sleep 10
			done
		fi
	done
}

# Sometimes the container starts running "too soon after reboot", before
# balenaOS finished initialization, such that commands like 'ipt6tables -N'
# fail with an error like:
#   ip6tables v1.8.7 (legacy): can't initialize ip6tables table `filter':
#       Table does not exist (do you need to insmod?)
# So we test and wait.
function await_os_initialization {
	until ip6tables -N IPV6-ROUTER-AWAIT &>/dev/null; do
		log 'Awaiting system initialization (ip6tables not ready)'
		sleep 1
	done
	ip6tables -X IPV6-ROUTER-AWAIT
}

function main {
	check_configuration
	prefix_fixup
	await_os_initialization
	setup_firewall
	configure_dnsmasq
	configure_radvd
	if [ "${TUNNEL_TYPE}" = 'he-6in4' ]; then
		check_6in4_mtu
		del_6in4_tunnel
		setup_6in4_tunnel
	fi
	if [ "${TUNNEL_TYPE}" = '6project-openvpn' ]; then
		run_service openvpn &
		run_service dnsmasq &
	fi
	setup_routing
	run_service radvd # here it blocks in a loop
}

function sigterm_handler {
	log "Terminating on signal..."
	del_6in4_tunnel
	for pidfile in /run/*.pid; do
		kill -TERM "$(cat "${pidfile}")"
	done
}

trap sigterm_handler TERM

if [ "${RUN_MODE}" = 'idle' ]; then
	# Idle mode for debugging
	until [ -e "${QUIT_FILE}" ]; do sleep 3; done
else
	# When executed without arguments, run 'main' in a child process
	# to allow orphan process detection with [ "${PPID}" = 1 ]
	if [ "$1" = 'main' ]; then
		main
	else
		"$0" main
	fi
fi

status="$?"
rm -f "${QUIT_FILE}"
exit "${status}"
