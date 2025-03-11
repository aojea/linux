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
#
# nsrouters implement loadbalancing using DNAT with a virtual IP
# 10.0.4.10 - dead:4::a
# shellcheck disable=SC2162,SC2317

source lib.sh
ret=0

timeout=15

cleanup()
{
	ip netns pids "$ns1" | xargs kill 2>/dev/null
	ip netns pids "$ns2" | xargs kill 2>/dev/null
	ip netns pids "$nsrouter" | xargs kill 2>/dev/null

	cleanup_all_ns
}

checktool "nft --version" "test without nft tool"
checktool "socat -h" "run test without socat"

trap cleanup EXIT
setup_ns ns1 ns2 nsrouter

if ! ip link add veth0 netns "$nsrouter" type veth peer name eth0 netns "$ns1" > /dev/null 2>&1; then
	echo "SKIP: No virtual ethernet pair device support in kernel"
	exit $ksft_skip
fi
ip link add veth1 netns "$nsrouter" type veth peer name eth0 netns "$ns2"

ip -net "$nsrouter" link set veth0 up
ip -net "$nsrouter" addr add 10.0.1.1/24 dev veth0
ip -net "$nsrouter" addr add dead:1::1/64 dev veth0 nodad

ip -net "$nsrouter" link set veth1 up
ip -net "$nsrouter" addr add 10.0.2.1/24 dev veth1
ip -net "$nsrouter" addr add dead:2::1/64 dev veth1 nodad


ip -net "$ns1" link set eth0 up
ip -net "$ns2" link set eth0 up

ip -net "$ns1" addr add 10.0.1.99/24 dev eth0
ip -net "$ns1" addr add dead:1::99/64 dev eth0 nodad
ip -net "$ns1" route add default via 10.0.1.1
ip -net "$ns1" route add default via dead:1::1

ip -net "$ns2" addr add 10.0.2.99/24 dev eth0
ip -net "$ns2" addr add dead:2::99/64 dev eth0 nodad
ip -net "$ns2" route add default via 10.0.2.1
ip -net "$ns2" route add default via dead:2::1


ip netns exec "$nsrouter" sysctl net.ipv6.conf.all.forwarding=1 > /dev/null
ip netns exec "$nsrouter" sysctl net.ipv4.conf.veth0.forwarding=1 > /dev/null
ip netns exec "$nsrouter" sysctl net.ipv4.conf.veth1.forwarding=1 > /dev/null

test_ping() {
	if ! ip netns exec "$ns1" ping -c 1 -q 10.0.2.99 > /dev/null; then
		return 1
	fi

	if ! ip netns exec "$ns1" ping -c 1 -q dead:2::99 > /dev/null; then
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

check_last_line() {
	local file="$1"
	local string="$2"

	local last_line=$(tail -n 1 "$file")
	# Compare the last line with the given string.
	if [[ "$last_line" == "$string" ]]; then
		return 0
	else
		return 1
	fi
}

test_tcp_connect() {
	local ns=$1
	local dest=$2
	local string=$3
	local outputfile=$4

	if ! echo "$string" | ip netns exec "$ns" socat -t 2 -T 2 -u STDIO tcp:"$dest" 2> /dev/null ; then
		return 1
	fi

	if ! busywait "$BUSYWAIT_TIMEOUT" check_last_line "$outputfile" "$string" &> /dev/null; then
		return 1
	else
		return 0
	fi
}

test_tcp_established() {
	local string=$1
	local inputfile=$2
	local outputfile=$3
	local timeout=$4

	echo "$string" >> "$inputfile"
	if ! busywait "$timeout" check_last_line "$outputfile" "$string" &> /dev/null; then
		return 1
	else
		return 0
	fi
}

process_does_not_exist()
{
	local pid=$1
	if ! kill -0 "$pid" 2>/dev/null ; then
		return 0
	else
		return 1
	fi
}

listener_ready()
{
	local ns="$1"
	local port="$2"
	local proto="$3"
	ss -N "$ns" -ln "$proto" -o "sport = :$port" | grep -q "$port"
}

test_conntrack_reject_established()
{
	local ip_proto="$1"
	local testname="$2-$ip_proto"
	local test_rules="$3"
	# derived variables
	local socat_ipproto
	local vip
	local vip_ip_port
	local ns2_ip
	local ns2_ip_port

	# socat 1.8.0 has a bug that requires to specify the IP family to bind (fixed in 1.8.0.1)
	case $ip_proto in
	"ip")
		socat_ipproto="-4"
		vip=10.0.4.10
		ns2_ip=10.0.2.99
		vip_ip_port="$vip:8080"
		ns2_ip_port="$ns2_ip:8080"
	;;
	"ip6")
		socat_ipproto="-6"
		vip=dead:4::a
		ns2_ip=dead:2::99
		vip_ip_port="[$vip]:8080"
		ns2_ip_port="[$ns2_ip]:8080"
	;;
	*)
	echo "FAIL: unsupported protocol"
	exit 255
	;;
	esac

	# nsroute expose ns2 server in a virtual IP using DNAT
	ip netns exec "$nsrouter" nft -f /dev/stdin <<EOF
flush ruleset
table inet nat {
	chain kube-proxy {
		type nat hook prerouting priority 0; policy accept;
		$ip_proto daddr $vip tcp dport 8080 dnat to $ns2_ip_port
	}
}
EOF

	TMPFILEIN=$(mktemp)
	TMPFILEOUT=$(mktemp)
	# set up a server in ns2
	timeout "$timeout" ip netns exec "$ns2" socat -u "$socat_ipproto" tcp-listen:8080,fork STDIO > "$TMPFILEOUT" 2> /dev/null &
	local server2_pid=$!

	busywait "$BUSYWAIT_TIMEOUT" listener_ready "$ns2" 8080 "-t"

	# request from ns1 to ns2 (direct traffic) should work
	if ! test_tcp_connect $ns1 $ns2_ip_port PING1 $TMPFILEOUT ; then
		echo "ERROR: $testname: fail to connect to $ns2_ip_port"
		ret=1
	else
		echo "PASS: $testname: ns1 connected succesfully to $ns2_ip_port"
	fi

	# set up a persistent connection through DNAT to ns2
	timeout "$timeout" tail -f $TMPFILEIN | ip netns exec "$ns1" socat STDIO tcp:"$vip_ip_port,sourceport=12345" 2> /dev/null &
	local client1_pid=$!

	# request from ns1 to vip (DNAT to ns2) on an existing connection
	# if we don't read from the pipe the traffic loops forever
	if ! test_tcp_established PING2 $TMPFILEIN $TMPFILEOUT $BUSYWAIT_TIMEOUT ; then
		echo "ERROR: $testname: fail to connect over the established connection to $vip_ip_port"
		ret=1
	else
		echo "PASS: $testname: ns1 connected succesfully over the established connection to $vip_ip_port"
	fi

	# request from ns1 to vip (DNAT to ns2) should work
	if ! test_tcp_connect $ns1 $vip_ip_port PING3 $TMPFILEOUT ; then
		echo "ERROR: $testname: fail to connect to $vip_ip_port"
		ret=1
	else
		echo "PASS: $testname: ns1 connected succesfully to $vip_ip_port"
	fi

	# request from ns1 to vip (DNAT to ns2) on an existing connection should work
	if ! test_tcp_established PING4 $TMPFILEIN $TMPFILEOUT $BUSYWAIT_TIMEOUT ; then
		echo "ERROR: $testname: fail to connect over the established connection to $vip_ip_port"
		ret=1
	else
		echo "PASS: $testname: ns1 connected succesfully over the established connection to $vip_ip_port"
	fi

	# add a rule to reject traffic to ns2 virtual ip and port
	eval "echo \"$test_rules\"" | ip netns exec "$nsrouter" nft -f /dev/stdin

	# request from ns1 to ns2 (direct traffic) must work
	if ! test_tcp_connect $ns1 $ns2_ip_port PING5 $TMPFILEOUT ; then
		echo "ERROR: $testname: fail to connect to $ns2_ip_port"
		ret=1
	else
		echo "PASS: $testname: ns1 connected succesfully to $ns2_ip_port"
	fi

	# request from ns1 to vip (DNAT to ns2) should fail
	if test_tcp_connect $ns1 $vip_ip_port PING6 $TMPFILEOUT ; then
		echo "ERROR: $testname: ns1 connected succesfully to $vip_ip_port"
		ret=1
	else
		echo "PASS: $testname: fail to connect to $vip_ip_port"
	fi

	# request from ns1 to vip (DNAT to ns2) on an existing connection should fail
	if test_tcp_established PING7 $TMPFILEIN $TMPFILEOUT 100 ; then
		echo "ERROR: $testname: ns1 connected succesfully to $vip_ip_port"
		ret=1
	else
		echo "PASS: $testname: fail to connect over the established connection to $vip_ip_port"
	fi

	if busywait 3000 process_does_not_exist "$client1_pid" ; then
		echo "PASS: $testname: persistent connection is closed as intended"
	else
		echo "ERROR: $testname: persistent connection is not closed as intended"
		kill $client1_pid 2>/dev/null
		ret=1
	fi

	kill $server2_pid 2>/dev/null
	rm -f "$TMPFILEIN"
	rm -f "$TMPFILEOUT"
}


if test_ping; then
	# queue bypass works (rules were skipped, no listener)
	echo "PASS: ${ns1} can reach ${ns2}"
else
	echo "FAIL: ${ns1} cannot reach ${ns2}: $ret" 1>&2
	exit $ret
fi

# Define different rule combinations
declare -A testcases

testcases["frontend filter"]='
flush table inet nat
table inet filter {
	chain kube-proxy {
		type filter hook prerouting priority -1; policy accept;
		$ip_proto daddr $vip tcp dport 8080 reject with tcp reset
	}
}'

testcases["backend filter"]='
table inet filter {
	chain kube-proxy {
		type filter hook forward priority -1; policy accept;
		ct original $ip_proto daddr $ns2_ip accept
		$ip_proto daddr $ns2_ip tcp dport 8080 reject with tcp reset
	}
}'


for testname in "${!testcases[@]}"; do
	test_conntrack_reject_established "ip" "$testname" "${testcases[$testname]}"
	test_conntrack_reject_established "ip6" "$testname" "${testcases[$testname]}"
done

exit $ret
