#!/usr/bin/env python3

# As of time of writing this is the only ai-generated part of I405, i promise :|
# it really shows lol

import subprocess
import time
import os
import re
import statistics
import sys
import signal
from typing import Any, Tuple, Optional

# Configuration variables
SERVER_NS_NAME: str = "i405-server"
CLIENT_NS_NAME: str = "i405-client"
BRIDGE_NS_NAME: str = "i405-bridge"
BRIDGE_NAME: str = "br-i405"
SERVER_VETH_BR: str = "veth-server-br"
SERVER_VETH_NS: str = "veth-server"
CLIENT_VETH_BR: str = "veth-client-br"
CLIENT_VETH_NS: str = "veth-client"

SERVER_VETH_IP: str = "192.168.99.0"
CLIENT_VETH_IP: str = "192.168.99.1"

SERVER_TUN_IP: str = "192.168.100.0"
CLIENT_TUN_IP: str = "192.168.100.1"

NUM_CAPTURED_PACKETS: int = 100
C2S_PACKETS_FILE: str = "tmp/c2s_packets.txt"
S2C_PACKETS_FILE: str = "tmp/s2c_packets.txt"

# The expected interval between packets in nanoseconds, as configured for the client
PACKET_INTERVAL_NS: int = 100000000

# Ensure we are running as root
if os.geteuid() != 0:
    print("Please run this script with sudo.")
    sys.exit(1)

def run_command(command, check=True, capture_output=False, text=False, **kwargs):
    """Helper to run shell commands."""
    print(f"Running: {' '.join(command)}")
    result = subprocess.run(command, check=check, capture_output=capture_output, text=text, **kwargs)
    if capture_output:
        print("Stdout:\n", result.stdout)
        print("Stderr:\n", result.stderr)
    return result

def run_command_ns(namespace: str, command: list[str], check: bool = True, capture_output: bool = False, text: bool = False, **kwargs: Any) -> subprocess.CompletedProcess:
    """Helper to run shell commands within a network namespace."""
    ns_command: list[str] = ["ip", "netns", "exec", namespace] + command
    return run_command(ns_command, check=check, capture_output=capture_output, text=text, **kwargs)

def cleanup() -> None:
    """Clean up network namespaces and interfaces."""
    print("Cleaning up any existing configurations...")
    # Use stderr=subprocess.DEVNULL to suppress "Cannot remove..." errors if they don't exist
    run_command(["ip", "netns", "del", SERVER_NS_NAME], check=False, stderr=subprocess.DEVNULL)
    run_command(["ip", "netns", "del", CLIENT_NS_NAME], check=False, stderr=subprocess.DEVNULL)
    run_command(["ip", "netns", "del", BRIDGE_NS_NAME], check=False, stderr=subprocess.DEVNULL)
    # Veth pairs in the bridge namespace are automatically cleaned up when the namespace is deleted.
    print("Cleanup complete.")

def setup_network() -> None:
    """Set up network namespaces, bridge, and veth pairs."""
    print("Setting up network namespaces...")

    # Create Network Namespaces
    run_command(["ip", "netns", "add", SERVER_NS_NAME])
    run_command(["ip", "netns", "add", CLIENT_NS_NAME])
    run_command(["ip", "netns", "add", BRIDGE_NS_NAME])

    # Configure loopback interface in each namespace
    run_command_ns(SERVER_NS_NAME, ["ip", "link", "set", "dev", "lo", "up"])
    run_command_ns(CLIENT_NS_NAME, ["ip", "link", "set", "dev", "lo", "up"])
    run_command_ns(BRIDGE_NS_NAME, ["ip", "link", "set", "dev", "lo", "up"])

    # Configure the Bridge Namespace
    run_command_ns(BRIDGE_NS_NAME, ["ip", "link", "add", "name", BRIDGE_NAME, "type", "bridge"])
    run_command_ns(BRIDGE_NS_NAME, ["ip", "link", "set", "dev", BRIDGE_NAME, "up"])

    # Create and Configure Veth Pairs for Server NS
    run_command(["ip", "link", "add", "name", SERVER_VETH_BR, "type", "veth", "peer", "name", SERVER_VETH_NS])
    run_command(["ip", "link", "set", SERVER_VETH_NS, "netns", SERVER_NS_NAME])
    run_command_ns(SERVER_NS_NAME, ["ip", "addr", "add", f"{SERVER_VETH_IP}/24", "dev", SERVER_VETH_NS])
    run_command(["ip", "link", "set", SERVER_VETH_BR, "netns", BRIDGE_NS_NAME])
    run_command_ns(BRIDGE_NS_NAME, ["ip", "link", "set", SERVER_VETH_BR, "master", BRIDGE_NAME])
    run_command_ns(BRIDGE_NS_NAME, ["ip", "link", "set", "dev", SERVER_VETH_BR, "up"])
    run_command_ns(SERVER_NS_NAME, ["ip", "link", "set", "dev", SERVER_VETH_NS, "up"])

    # Create and Configure Veth Pairs for Client NS
    run_command(["ip", "link", "add", "name", CLIENT_VETH_BR, "type", "veth", "peer", "name", CLIENT_VETH_NS])
    run_command(["ip", "link", "set", CLIENT_VETH_NS, "netns", CLIENT_NS_NAME])
    run_command_ns(CLIENT_NS_NAME, ["ip", "addr", "add", f"{CLIENT_VETH_IP}/24", "dev", CLIENT_VETH_NS])
    run_command(["ip", "link", "set", CLIENT_VETH_BR, "netns", BRIDGE_NS_NAME])
    run_command_ns(BRIDGE_NS_NAME, ["ip", "link", "set", CLIENT_VETH_BR, "master", BRIDGE_NAME])
    run_command_ns(BRIDGE_NS_NAME, ["ip", "link", "set", "dev", CLIENT_VETH_BR, "up"])
    run_command_ns(CLIENT_NS_NAME, ["ip", "link", "set", "dev", CLIENT_VETH_NS, "up"])

    print("Network namespaces set up")

def analyze_packets_file(filepath: str) -> dict[str, float]:
    """Analyzes tcpdump output for timestamp deviations."""
    print(f"Analyzing packet file: {filepath}")
    timestamps: list[float] = []
    try:
        with open(filepath, 'r') as f:
            # Skip the first line (tcpdump header)
            next(f)
            for line in f:
                match = re.match(r"\d+\.\d+", line)
                if match:
                    timestamps.append(float(match.group()))
    except FileNotFoundError:
        print(f"Error: Packet file not found at {filepath}")
        raise AssertionError(f"Packet file not found: {filepath}")

    if len(timestamps) < 2:
        print("Not enough timestamps to analyze.")
        raise AssertionError(f"Not enough timestamps to analyze in {filepath} (found {len(timestamps)})")

    # Calculate deviations from expected interval (0.1 seconds or 100ms)
    # The shell script calculated deviation from the *previous* packet,
    # which is simpler for a fixed interval. Let's replicate that.
    deviations: list[float] = []
    # Convert the nanosecond interval to seconds for comparison with tcpdump timestamps
    expected_interval_sec: float = PACKET_INTERVAL_NS / 1e9
    for i in range(1, len(timestamps)):
        actual_interval: float = timestamps[i] - timestamps[i-1]
        deviations.append(actual_interval - expected_interval_sec)

    if not deviations:
        print("No deviations calculated.")
        raise AssertionError(f"No deviations calculated from timestamps in {filepath}")

    avg_deviation: float = statistics.mean(deviations)
    # Worst deviation is the max absolute deviation
    worst_deviation: float = max(abs(d) for d in deviations)
    stddev_deviation: float = statistics.stdev(deviations) if len(deviations) > 1 else 0.0

    # Convert to nanoseconds for comparison with shell script output format
    avg_ns: float = avg_deviation * 1e9
    worst_ns: float = worst_deviation * 1e9
    stddev_ns: float = stddev_deviation * 1e9

    print(f"Avg:    {avg_ns:.9f}")
    print(f"Worst:  {worst_ns:.9f}")
    print(f"Stddev: {stddev_ns:.9f}")

    return {"avg": avg_ns, "worst": worst_ns, "stddev": stddev_ns}

def main() -> None:
    """Main function to run the end-to-end test."""
    # Ensure tmp directory exists
    os.makedirs("tmp", exist_ok=True)

    # Register cleanup on exit signals
    signal.signal(signal.SIGINT, lambda sig, frame: (cleanup(), sys.exit(1)))
    signal.signal(signal.SIGTERM, lambda sig, frame: (cleanup(), sys.exit(1)))

    try:
        cleanup() # Ensure a clean state before starting
        setup_network()

        print("Starting I405 server and client...")
        server_process = subprocess.Popen(
            ["ip", "netns", "exec", SERVER_NS_NAME,
             "./target/debug/i405-tunnel", "server", "--password", "password",
             "--tun-name", "i405-server-tun", "--tun-ipv4", f"{SERVER_TUN_IP}/24"],
        )
        client_process = subprocess.Popen(
            ["ip", "netns", "exec", CLIENT_NS_NAME,
             "./target/debug/i405-tunnel", "client", "--peer", f"{SERVER_VETH_IP}:1405",
             "--password", "password", "--tun-name", "i405-client-tun",
             "--tun-ipv4", f"{CLIENT_TUN_IP}/24", "--outgoing-packet-length", "1000",
             "--outgoing-packet-interval", f"{PACKET_INTERVAL_NS}ns", "--incoming-packet-length", "1000",
             "--incoming-packet-interval", f"{PACKET_INTERVAL_NS}ns"],
        )
        time.sleep(0.5) # wait for handshake

        print("Ping test: Roundtrips should be between 100ms and 210ms")
        ping_times: list[float] = []
        try:
            # Ping from server NS to client TUN IP
            ping_server_result: subprocess.CompletedProcess = run_command_ns(SERVER_NS_NAME, ["ping", "-c1", "-w1", CLIENT_TUN_IP], capture_output=True, text=True)
            # Ping from client NS to server TUN IP
            ping_client_result: subprocess.CompletedProcess = run_command_ns(CLIENT_NS_NAME, ["ping", "-c1", "-w1", SERVER_TUN_IP], capture_output=True, text=True)

            # Extract ping times
            for result in [ping_server_result, ping_client_result]:
                match: re.Match | None = re.search(r"time=(\d+\.?\d*)\s*ms", result.stdout)
                if match:
                    ping_times.append(float(match.group(1)))
                else:
                    print("Error: Could not extract ping time from output.")
                    raise AssertionError(f"Could not extract ping time from output: {result.stdout}")

        except subprocess.CalledProcessError as e:
            print(f"Ping failed: {e}")
            print("Stdout:", e.stdout)
            print("Stderr:", e.stderr)
            sys.exit(1)

        # Assert ping times
        print("Asserting ping times...")
        assert len(ping_times) == 2, f"Expected 2 ping results, got {len(ping_times)}"
        for ping_time in ping_times:
            # I once saw it be 99.0ms. Not really sure how that's possible TBH
            assert 99 <= ping_time <= 210, f"Unexpected ping time: {ping_time} ms"
        print("Ping assertions passed.")

        # Packet capture
        print(f"Measuring client->server packet timestamp deviations {NUM_CAPTURED_PACKETS} packets...")
        tcpdump_c2s: subprocess.CompletedProcess = run_command_ns(
            BRIDGE_NS_NAME,
            ["tcpdump", "-c", str(NUM_CAPTURED_PACKETS), "--nano", "-n", "-tt",
             "udp port 1405 and dst host " + SERVER_VETH_IP],
            capture_output=True, text=True, check=True
        )
        with open(C2S_PACKETS_FILE, "w") as f:
            f.write(tcpdump_c2s.stdout)

        print(f"Measuring server->client packet timestamp deviations {NUM_CAPTURED_PACKETS} packets...")
        tcpdump_s2c: subprocess.CompletedProcess = run_command_ns(
            BRIDGE_NS_NAME,
            ["tcpdump", "-c", str(NUM_CAPTURED_PACKETS), "--nano", "-n", "-tt",
             "udp port 1405 and src host " + SERVER_VETH_IP],
            capture_output=True, text=True, check=True
        )
        with open(S2C_PACKETS_FILE, "w") as f:
            f.write(tcpdump_s2c.stdout)

        # Analyze and assert packet statistics
        print("Analyzing and asserting packet statistics...")
        c2s_stats: dict[str, float] = analyze_packets_file(C2S_PACKETS_FILE)
        s2c_stats: dict[str, float] = analyze_packets_file(S2C_PACKETS_FILE)

        assert 0 < abs(c2s_stats["avg"]) < 1000, f"Unacceptable C2S average: {c2s_stats['avg']}"
        assert 0 < abs(c2s_stats["worst"]) < 1_000_000, f"Unacceptable C2S worst: {c2s_stats['worst']}"
        assert 0 < abs(c2s_stats["stddev"]) < 100_000, f"Unacceptable C2S stddev: {c2s_stats['stddev']}"

        assert 0 < abs(s2c_stats["avg"]) < 1000, f"Unacceptable S2C average: {s2c_stats['avg']}"
        assert 0 < abs(s2c_stats["worst"]) < 1_000_000, f"Unacceptable S2C worst: {s2c_stats['worst']}"
        assert 0 < abs(s2c_stats["stddev"]) < 100_000, f"Unacceptable S2C stddev: {s2c_stats['stddev']}"

        print("Packet statistics assertions passed.")

    finally:
        # Terminate processes before cleanup
        print("Terminating background processes...")
        # Check if the variable exists and the process is still running
        if 'server_process' in locals() and isinstance(server_process, subprocess.Popen) and server_process.poll() is None:
            server_process.terminate()
        if 'client_process' in locals() and isinstance(client_process, subprocess.Popen) and client_process.poll() is None:
            client_process.terminate()
        # Give them a moment to exit
        time.sleep(0.5) # Give processes a bit more time to terminate gracefully
        # Kill if they didn't terminate
        if 'server_process' in locals() and isinstance(server_process, subprocess.Popen) and server_process.poll() is None:
             print("Server process did not terminate, killing...")
             server_process.kill()
        if 'client_process' in locals() and isinstance(client_process, subprocess.Popen) and client_process.poll() is None:
             print("Client process did not terminate, killing...")
             client_process.kill()

        cleanup() # Always clean up network namespaces and interfaces

    # TODO test that SIGINT to the server shuts it down. But this might have to wait until we've
    # decided exactly what behavior we /want/

    print("End-to-end test completed successfully.")

if __name__ == "__main__":
    main()
