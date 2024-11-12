#!/bin/bash
#
# This tests conntrack on the following scenario:
#
#                         +------------+
# +-------+               |  nsrouter  |                  +-------+
# |ns1    |.99          .1|            |.1             .99|    ns2|
# |   eth0|---------------|veth0  veth1|------------------|eth0   |
# |       |  10.0.1.0/24  |            |   10.0.2.0/24    |       |
# +-------+  dead:1::/64  |    veth2   |   dead:2::/64    +-------+
#                         +------------+
#                                |.1
#                                |
#                                |
#                                |                        +-------+
#                                |                     .99|    ns3|
#                                +------------------------|eth0   |
#                                       10.0.3.0/24       |       |
#                                       dead:3::/64       +-------+
#
# nsrouters implement loadbalancing using DNAT with a virtual IP
# 10.0.4.10 - dead:4::a
# shellcheck disable=SC2162,SC2317

source lib.sh
ret=0
# UDP is slow
timeout=15

cleanup()
{
	ip netns pids "$ns1" | xargs kill 2>/dev/null
	ip netns pids "$ns2" | xargs kill 2>/dev/null
	ip netns pids "$ns3" | xargs kill 2>/dev/null
	ip netns pids "$nsrouter" | xargs kill 2>/dev/null

	cleanup_all_ns
}

checktool "nft --version" "test without nft tool"
checktool "socat -h" "run test without socat"

trap cleanup EXIT
setup_ns ns1 ns2 ns3 nsrouter

if ! ip link add veth0 netns "$nsrouter" type veth peer name eth0 netns "$ns1" > /dev/null 2>&1; then
    echo "SKIP: No virtual ethernet pair device support in kernel"
    exit $ksft_skip
fi
ip link add veth1 netns "$nsrouter" type veth peer name eth0 netns "$ns2"
ip link add veth2 netns "$nsrouter" type veth peer name eth0 netns "$ns3"

ip -net "$nsrouter" link set veth0 up
ip -net "$nsrouter" addr add 10.0.1.1/24 dev veth0
ip -net "$nsrouter" addr add dead:1::1/64 dev veth0 nodad

ip -net "$nsrouter" link set veth1 up
ip -net "$nsrouter" addr add 10.0.2.1/24 dev veth1
ip -net "$nsrouter" addr add dead:2::1/64 dev veth1 nodad

ip -net "$nsrouter" link set veth2 up
ip -net "$nsrouter" addr add 10.0.3.1/24 dev veth2
ip -net "$nsrouter" addr add dead:3::1/64 dev veth2 nodad

ip -net "$ns1" link set eth0 up
ip -net "$ns2" link set eth0 up
ip -net "$ns3" link set eth0 up

ip -net "$ns1" addr add 10.0.1.99/24 dev eth0
ip -net "$ns1" addr add dead:1::99/64 dev eth0 nodad
ip -net "$ns1" route add default via 10.0.1.1
ip -net "$ns1" route add default via dead:1::1

ip -net "$ns2" addr add 10.0.2.99/24 dev eth0
ip -net "$ns2" addr add dead:2::99/64 dev eth0 nodad
ip -net "$ns2" route add default via 10.0.2.1
ip -net "$ns2" route add default via dead:2::1

ip -net "$ns3" addr add 10.0.3.99/24 dev eth0
ip -net "$ns3" addr add dead:3::99/64 dev eth0 nodad
ip -net "$ns3" route add default via 10.0.3.1
ip -net "$ns3" route add default via dead:3::1

ip netns exec "$nsrouter" sysctl net.ipv6.conf.all.forwarding=1 > /dev/null
ip netns exec "$nsrouter" sysctl net.ipv4.conf.veth0.forwarding=1 > /dev/null
ip netns exec "$nsrouter" sysctl net.ipv4.conf.veth1.forwarding=1 > /dev/null
ip netns exec "$nsrouter" sysctl net.ipv4.conf.veth2.forwarding=1 > /dev/null

test_ping() {
  if ! ip netns exec "$ns1" ping -c 1 -q 10.0.2.99 > /dev/null; then
	return 1
  fi

  if ! ip netns exec "$ns1" ping -c 1 -q dead:2::99 > /dev/null; then
	return 2
  fi

  if ! ip netns exec "$ns1" ping -c 1 -q 10.0.3.99 > /dev/null; then
	return 1
  fi

  if ! ip netns exec "$ns1" ping -c 1 -q dead:3::99 > /dev/null; then
	return 2
  fi

  return 0
}

test_ping_router() {
  if ! ip netns exec "$ns1" ping -c 1 -q 10.0.2.1 > /dev/null; then
	return 3
  fi

  if ! ip netns exec "$ns1" ping -c 1 -q dead:2::1 > /dev/null; then
	return 4
  fi

  return 0
}


listener_ready()
{
	local ns="$1"
	local port="$2"
	local proto="$3"
	ss -N "$ns" -ln "$proto" -o "sport = :$port" | grep -q "$port"
}

test_conntrack_udp_expires()
{
	local ip_proto="$1"
	# derived variables
	local testname="test_${ip_proto}_udp_forward"
	local socat_ipproto
	local vip
	local ns2_ip
	local ns3_ip
	local ns2_ip_port
	local ns3_ip_port

	# socat 1.8.0 has a bug that requires to specify the IP family to bind (fixed in 1.8.0.1)
	case $ip_proto in
	"ip")
		socat_ipproto="-4"
		vip=10.0.4.10
		ns2_ip=10.0.2.99
		ns3_ip=10.0.3.99
		vip_ip_port="$vip:8080"
		ns2_ip_port="$ns2_ip:8080"
		ns3_ip_port="$ns3_ip:8080"
	;;
	"ip6")
		socat_ipproto="-6"
		vip=dead:4::a
		ns2_ip=dead:2::99
		ns3_ip=dead:3::99
		vip_ip_port="[$vip]:8080"
		ns2_ip_port="[$ns2_ip]:8080"
		ns3_ip_port="[$ns3_ip]:8080"
	;;
	*)
	echo "FAIL: unsupported protocol"
	exit 255
	;;
	esac

	ip netns exec "$nsrouter" nft -f /dev/stdin <<EOF
flush ruleset
table inet nat {
	chain kube-proxy {
		type nat hook prerouting priority 0; policy accept;
		$ip_proto daddr $vip udp dport 8080 dnat to $ns2_ip_port
	}
}
EOF
	# Set low UDP timeouts to make the test faster since it has to wait for the conntrack entries to expire
	ip netns exec "$nsrouter" bash -c 'printf 5 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout'
	ip netns exec "$nsrouter" bash -c 'printf 5 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream'

	timeout "$timeout" ip netns exec "$ns2" socat "$socat_ipproto" udp-listen:8080,fork SYSTEM:"echo PONG_NS2" 2>/dev/null &
	local server2_pid=$!

	timeout "$timeout" ip netns exec "$ns3" socat "$socat_ipproto" udp-listen:8080,fork SYSTEM:"echo PONG_NS3" 2>/dev/null &
	local server3_pid=$!

	busywait "$BUSYWAIT_TIMEOUT" listener_ready "$ns2" 8080 "-u"
	busywait "$BUSYWAIT_TIMEOUT" listener_ready "$ns3" 8080 "-u"

	local result
	# request from ns1 to ns2 (direct traffic)
	result=$(echo PING | ip netns exec "$ns1" socat -t 2 -T 2 STDIO udp:"$ns2_ip_port",sourceport=18888)
	if [ "$result" == "PONG_NS2" ] ;then
		echo "PASS: $testname: ns1 got reply \"$result\" connecting to ns2"
	else
		echo "ERROR: $testname: ns1 got reply \"$result\" connecting to ns2, not \"PONG_NS2\" as intended"
		ret=1
	fi

	# request from ns1 to ns3 (direct traffic)
	result=$(echo PING | ip netns exec "$ns1" socat -t 2 -T 2 STDIO udp:"$ns3_ip_port",sourceport=18888)
	if [ "$result" = "PONG_NS3" ] ;then
		echo "PASS: $testname: ns1 got reply \"$result\" connecting to ns3"
	else
		echo "ERROR: $testname: ns1 got reply \"$result\" connecting to ns3, not \"PONG_NS3\" as intended"
		ret=1
	fi

	# request from ns1 to vip (DNAT to ns2)
	result=$(echo PING | ip netns exec "$ns1" socat -t 2 -T 2 STDIO udp:"$vip_ip_port",sourceport=18888)
	if [ "$result" = "PONG_NS2" ] ;then
		echo "PASS: $testname: ns1 got reply \"$result\" connecting to vip (ns2)"
	else
		echo "ERROR: $testname: ns1 got reply \"$result\" connecting to vip, not \"PONG_NS2\" as intended"
		ret=1
	fi

	# kill the server listening in ns2
	kill $server2_pid 2>/dev/null

	# replace the DNAT rule to direct and replace ns2 destination with ns3
	ip netns exec "$nsrouter" nft -f /dev/stdin <<EOF
flush ruleset
table inet nat {
	chain kube-proxy {
		type nat hook prerouting priority 0; policy accept;
		$ip_proto daddr $vip udp dport 8080 dnat to $ns3_ip_port
	}
}
EOF

	# requests from ns1 to vip (DNAT to ns3) should fail but not renew the conntrack entry
	# once the conntrack entry expires it should receive the response from the ns3
	# we have to reuse the same port to hit the existing conntrack entry
	for i in $(seq 1 20) ; do
		result=$(echo PING | ip netns exec "$ns1" socat -t 2 -T 2 STDIO udp:"$vip_ip_port",sourceport=18888)
		if [ "$result" = "PONG_NS3" ] ;then
			echo "PASS: $testname: ns1 got reply \"$result\" connecting to vip (ns3)"
			return
		else
			echo "LOG: $testname: ns1 got reply \"$result\" connecting to vip, retrying ..."
		fi
		sleep .5
	done
	# there was not answer from ns3
	echo "ERROR: $testname: ns1 did not get reply connecting to vip after 20 attempts"
	ret=1
}


if test_ping; then
	# queue bypass works (rules were skipped, no listener)
	echo "PASS: ${ns1} can reach ${ns2}"
else
	echo "FAIL: ${ns1} cannot reach ${ns2}: $ret" 1>&2
	exit $ret
fi

test_conntrack_udp_expires "ip"
test_conntrack_udp_expires "ip6"

exit $ret
