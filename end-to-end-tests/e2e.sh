#!/bin/bash

# In contrast to the rest of I405, this is mostly written by AI :)

set -euo pipefail

trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

# This script creates three network namespaces and connects two of them to a bridge
# in the third namespace using veth pairs. It explicitly uses 'sudo' for commands
# requiring superuser privileges.

# Configuration variables
NS1_NAME="i405-server"
NS2_NAME="i405-client"
BRIDGE_NS_NAME="i405-bridge"
BRIDGE_NAME="br-i405"
VETH1_BR="veth-server-br"
VETH1_NS1="veth-server"
VETH2_BR="veth-client-br"
VETH2_NS2="veth-client"

VETH1_IP="192.168.99.0"
VETH2_IP="192.168.99.1"

SERVER_TUN_IP="192.168.100.0"
CLIENT_TUN_IP="192.168.100.1"

NUM_CAPTURED_PACKETS=100
C2S_PACKETS_FILE="c2s_packets.txt"
S2C_PACKETS_FILE="s2c_packets.txt"

# --- Clean up previous configurations (optional, for re-running the script) ---
echo "Cleaning up any existing configurations..."
# Use '|| true' to prevent script from exiting if namespace doesn't exist
sudo ip netns del "$NS1_NAME" 2>/dev/null || true
sudo ip netns del "$NS2_NAME" 2>/dev/null || true
sudo ip netns del "$BRIDGE_NS_NAME" 2>/dev/null || true
echo "Cleanup complete."
sleep 0.2 # Give a moment for cleanup to fully propagate TODO is this not instant? is the AI lying to me?

# --- Create Network Namespaces ---
sudo ip netns add "$NS1_NAME"
sudo ip netns add "$NS2_NAME"
sudo ip netns add "$BRIDGE_NS_NAME"

# --- Configure loopback interface in each namespace ---
sudo ip netns exec "$NS1_NAME" ip link set dev lo up
sudo ip netns exec "$NS2_NAME" ip link set dev lo up
sudo ip netns exec "$BRIDGE_NS_NAME" ip link set dev lo up

# --- Configure the Bridge Namespace ---
sudo ip netns exec "$BRIDGE_NS_NAME" ip link add name "$BRIDGE_NAME" type bridge
sudo ip netns exec "$BRIDGE_NS_NAME" ip link set dev "$BRIDGE_NAME" up

# --- Create and Configure Veth Pairs for NS1 ---
# Create veth pair in the default namespace first
sudo ip link add name "$VETH1_BR" type veth peer name "$VETH1_NS1"
sudo ip link set "$VETH1_NS1" netns "$NS1_NAME"
sudo ip netns exec "$NS1_NAME" ip addr add "$VETH1_IP/24" dev "$VETH1_NS1"

# Move the bridge-side of the veth pair into the bridge namespace
sudo ip link set "$VETH1_BR" netns "$BRIDGE_NS_NAME"

sudo ip netns exec "$BRIDGE_NS_NAME" ip link set "$VETH1_BR" master "$BRIDGE_NAME"
sudo ip netns exec "$BRIDGE_NS_NAME" ip link set dev "$VETH1_BR" up

sudo ip netns exec "$NS1_NAME" ip link set dev "$VETH1_NS1" up

# --- Create and Configure Veth Pairs for NS2 ---
# Create veth pair in the default namespace first
sudo ip link add name "$VETH2_BR" type veth peer name "$VETH2_NS2"
sudo ip link set "$VETH2_NS2" netns "$NS2_NAME"
sudo ip netns exec "$NS2_NAME" ip addr add "$VETH2_IP/24" dev "$VETH2_NS2"

# Move the bridge-side of the veth pair into the bridge namespace
sudo ip link set "$VETH2_BR" netns "$BRIDGE_NS_NAME"

sudo ip netns exec "$BRIDGE_NS_NAME" ip link set "$VETH2_BR" master "$BRIDGE_NAME"
sudo ip netns exec "$BRIDGE_NS_NAME" ip link set dev "$VETH2_BR" up

sudo ip netns exec "$NS2_NAME" ip link set dev "$VETH2_NS2" up

echo "Network namespaces set up"

sudo ip netns exec "$NS1_NAME" ./target/debug/i405-tunnel server --password password --tun-name i405-server-tun --tun-ipv4 "$SERVER_TUN_IP/24" &
sudo ip netns exec "$NS2_NAME" ./target/debug/i405-tunnel client --peer "$VETH1_IP:1405" --password password --tun-name i405-client-tun --tun-ipv4 "$CLIENT_TUN_IP/24" --outgoing-packet-length 1000 --outgoing-packet-interval 100000000 --incoming-packet-length 1000 --incoming-packet-interval 100000000 &

sleep 0.5 # wait for handshake
echo "Ping test: Roundtrips should be between 100ms and 200ms"
sudo ip netns exec "$NS1_NAME" ping -c1 -w1 "$CLIENT_TUN_IP"
sudo ip netns exec "$NS2_NAME" ping -c1 -w1 "$SERVER_TUN_IP"

analyze_packets_file() {
    awk -F' ' '
function abs(x) {return x < 0 ? -x : x}
function max(a, b) {return a > b ? a : b}
NR>1{
  cur_delay = ($1-prev-0.1);
  total+=cur_delay;
  worst=max(abs(cur_delay),abs(worst))
}
{prev = $1}
END{printf "Avg:   %.9f\nWorst: %.9f\n", total/(NR-1), worst}
' < "$1"
}

echo "Measuring client->server packet timestamp deviations $NUM_CAPTURED_PACKETS packets..."
sudo ip netns exec "$BRIDGE_NS_NAME" tcpdump -c "$NUM_CAPTURED_PACKETS" --nano -n -tt "udp port 1405 and dst host $VETH1_IP" >"$C2S_PACKETS_FILE" 2>/dev/null
analyze_packets_file "$C2S_PACKETS_FILE"
echo "Measuring server->client packet timestamp deviations $NUM_CAPTURED_PACKETS packets..."
sudo ip netns exec "$BRIDGE_NS_NAME" tcpdump -c "$NUM_CAPTURED_PACKETS" --nano -n -tt "udp port 1405 and src host $VETH1_IP" >"$S2C_PACKETS_FILE" 2>/dev/null
analyze_packets_file "$S2C_PACKETS_FILE"
