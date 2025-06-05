#!/bin/bash
set -x

if [ "$1" = "" ]; then
    index=0
else
    index=$1
fi

if [ "$2" = "" ]; then
    experiments=1
else
    experiments=$2
fi

if ! [ -e "client${index}.conf" -a -e "server${index}.conf" ]; then
    echo Either client${index}.conf or server${index}.conf does not exist
    exit 1
fi


export PATH=$(realpath $(dirname $0)/../../wireguard-tools/src):$PATH

##########################
# Setup network namespaces
##########################

SERVER_VETH_LL_ADDR=00:00:00:00:01:$(printf "%02d" ${index})
SERVER_NS=srv${index}_ns
SERVER_VETH=srv${index}_ve

CLIENT_NS=cli${index}_ns
CLIENT_VETH_LL_ADDR=00:00:00:00:02:$(printf "%02d" ${index})
CLIENT_VETH=cli${index}_ve

ip netns add ${SERVER_NS}
ip netns add ${CLIENT_NS}
ip link add \
   name ${SERVER_VETH} \
   address ${SERVER_VETH_LL_ADDR} \
   netns ${SERVER_NS} \
   type veth \
   peer name ${CLIENT_VETH} \
   address ${CLIENT_VETH_LL_ADDR} \
   netns ${CLIENT_NS}

ip netns exec ${SERVER_NS} \
   ip link set dev ${SERVER_VETH} up
ip netns exec ${SERVER_NS} \
   ip link set dev lo up
ip netns exec ${SERVER_NS} \
    ip addr add 10.$((20+$index)).0.1/24 dev ${SERVER_VETH}

ip netns exec ${CLIENT_NS} \
    ip addr add 10.$((20 + $index)).0.2/24 dev ${CLIENT_VETH}
ip netns exec ${CLIENT_NS} \
   ip link set dev lo up
ip netns exec ${CLIENT_NS} \
   ip link set dev ${CLIENT_VETH} up
ip netns exec ${CLIENT_NS} \
   ip link set dev lo up

ip netns exec ${SERVER_NS} \
   ip neigh add 10.$((20 + $index)).0.2 \
      lladdr ${CLIENT_VETH_LL_ADDR} \
      dev ${SERVER_VETH}
ip netns exec ${CLIENT_NS} \
   ip neigh add 10.$((20 + $index)).0.1 \
      lladdr ${SERVER_VETH_LL_ADDR} \
      dev ${CLIENT_VETH}

# Turn off optimizations
# that dent realism.
ip netns exec ${CLIENT_NS} \
   ethtool -K ${CLIENT_VETH} gso off gro off tso off

ip netns exec ${SERVER_NS} \
   ethtool -K ${SERVER_VETH} gso off gro off tso off

ip netns exec ${CLIENT_NS} \
   tc qdisc add \
      dev ${CLIENT_VETH} \
      root netem \
      limit 1000 \
      delay 15.458ms \
      rate 1000mbps

ip netns exec ${SERVER_NS} \
   tc qdisc add \
      dev ${SERVER_VETH} \
      root netem \
      limit 1000 \
      delay 15.458ms \
      rate 1000mbps

ip netns exec ${SERVER_NS} iptables -t nat -A POSTROUTING -o ${SERVER_VETH} -j MASQUERADE
ip netns exec ${CLIENT_NS} iptables -t nat -A POSTROUTING -o ${CLIENT_VETH} -j MASQUERADE

ip netns exec ${SERVER_NS} \
    $(pwd)/wg-quick up ./server${index}.conf

ip netns exec ${CLIENT_NS} \
    $(pwd)/wg-quick up ./client${index}.conf


address=$(sed -n 's@Address = \(10\(\.[[:digit:]]\{1,3\}\)\+\)/24@\1@p' server${index}.conf)

sleep 10

ip netns exec ${CLIENT_NS} ping -c $experiments -t1 -i4.5 $address

