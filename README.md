# IPv6 Router project

## TL;DR

Add IPv6 to your local IPv4 network by connecting a balena device to it.

The balena device becomes an "add on" router on the local network, alongside the
existing IPv4 WiFi router.

This is achieved by bringing up a network tunnel based on either the 6in4 protocol
or OpenVPN, and then advertising the IPv6 prefix/subnet to devices on the local network.
We have tested the solution with tunnels provided by Hurricane Electric's
https://tunnelbroker.net/ in the case of 6in4, and https://6project.org/ in the case
of OpenVPN.

## Audience

Software developers, testers or enthusiasts who would like to use/test IPv6 but who have
only got IPv4. Many of us work in home/office networks that still only provide IPv4,
making it difficult to test with IPv6. This project hopes to make it easier to get hold of
IPv6 through network tunnels and a balena device.

**Some knowledge of IPv4 and IPv6 network configuration is required, not just to make
sense of it but also because this project has had limited testing and you are likely to
come across defects that will require some investigation on your part.** Your contribution
with fixes will be most welcome!

## Getting Started

You will need to register / request a tunnel from either tunnelbroker.net or
6project.org.

> **Disclaimer**  
> _This project is not associated with Hurricane Electric / tunnelbroker.net nor
> 6project.org, in any capacity. We don't get commission or anything like that! We mention
> them because we happen to have tested this project with the tunnel services offered by
> those companies, at one point in time. There is no guarantee, express or implied, that
> either tunnel will be feasible in your local network. **Furthermore, this project has
> had limited testing and may cause instability in your local network.** Consider using
> the whitelisting feature to mitigate the impact of misconfigurations._

Which one to choose? Some considerations:

* Tunnelbroker.net is free of charge and fast, and our preference when feasible.
  But it is often not feasible because:
  * It requires your existing WiFi router to be ping'able on the public IPv4 address
    (WAN interface -- this is usually configurable in the WiFi router settings, if you
    have admin access to it).
  * It uses the 6in4 protocol which, at the transport layer, uses neither TCP nor UDP,
    but rather [protocol number
    41](https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers), "IPv6 Encapsulation".
    Many NAT routers are OK with this, but many others will simply drop the packets and
    prevent the use of 6in4.

* 6project.org offers greater compatibility with WiFi routers (IPv4 NAT traversal) thanks
  to the use of OpenVPN over UDP, and will be feasible in a wider range of local networks.
  But it has downsides too:
  * It is a paid service (though a cheap one-off "donation").
  * In our experience, has lower bandwidth (slower) and higher latency (high ping time)
    compared to Tunnelbroker.net.
  * Offers a single /80 IPv6 prefix, while Tunnelbroker.net offers two /64 prefixes by
    default. The /80 prefix prevents client autoconfiguration (SLAAC) through router
    advertisements, requiring the use of DHCPv6. We manage to make it work, though.
  * [Android phones don't work with
    DHCPv6](https://en.wikipedia.org/wiki/Comparison_of_IPv6_support_in_operating_systems),
    so if you use 6project.org, Android phones won't get IPv6.
  * Even UDP can be problematic with regard to NAT traversal, especially Carrier Grade NAT
    that is often used in mobile/cell networks (e.g. smartphone hotspots). So even an
    OpenVPN tunnel will not be feasible in all environments.

### Setting up a Hurricane Electric Tunnel

** Work in Progress **

### Setting up a 6project.org tunnel

** Work in Progress **

_Instructions valid as of 12 Oct 2021_

After you register with 6project.org (and pay the donation), you will be sent a
zip file containing an OpenVPN client configuration file, likely with file
extension `.ovpn`. Replace the existing, empty './router/openvpn-client.conf'
file with that file.

### Environment variable configuration

** Work in Progress **

Both ROUTED_PREFIX and TUNNEL_PREFIX must be set, but they may have the same
value if you have only got one IPv6 prefix (e.g. a /80 prefix from 6project.org).
When this is the case, the IPv6 Router will automatically split the prefix in two
by adding one to prefix length, so that:  
  * The Tunnel Prefix is changed from e.g. a:b::/80 to a:b::/81
  * The Routed Prefix is changed from e.g. a:b::/80 to a:b:8000::/81

The Routed Prefix is assigned to the ${ROUTER_INTERFACE} (e.g. 'eth0'), and
the Tunnel Prefix is assigned to the tunnel interface, e.g. 'he-sit' or 'tun0'.
