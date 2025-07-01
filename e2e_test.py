#!/usr/bin/env python3

# As of time of writing this is the only ai-generated part of I405, i promise :|
# it really shows lol

import subprocess
import shlex
import time
import os
import re
import statistics
import sys
import signal
from typing import Any, Tuple, Optional

# Configuration variables
SERVER_NS: str = "i405-server"
CLIENT_NS: str = "i405-client"
SERVER_VETH: str = "veth-server"
CLIENT_VETH: str = "veth-client"

SERVER_VETH_IP: str = "192.168.99.0"
CLIENT_VETH_IP: str = "192.168.99.1"
SERVER_PORT: int = 1405
CLIENT_PORT: int = 11405

SERVER_TUN_IP: str = "192.168.100.0"
CLIENT_TUN_IP: str = "192.168.100.1"

PACKET_INTERVAL_MS = 100
PASSWORD = "password"

I405_BINARY_PATH = "./target/debug/i405-tunnel"
I405_ENV = {"RUST_BACKTRACE": "1"} | os.environ

# we run our tests across all poll modes, and use this global variable to keep track of which one is currently set
global_poll_mode: str = "undefined"

# so we can terminate everything when we clean up
all_popens: list[subprocess.Popen[bytes]] = []

def default_client_args() -> dict[str, str]:
    global global_poll_mode
    return {
        "peer": f"{SERVER_VETH_IP}:{SERVER_PORT}",
        "poll-mode": global_poll_mode,
        "password": PASSWORD,
        "tun-ipv4": f"{CLIENT_TUN_IP}/24",
        "tun-name": "i405-client-tun",
        "outgoing-packet-interval": f"{PACKET_INTERVAL_MS}ms",
        "incoming-packet-interval": f"{PACKET_INTERVAL_MS}ms",
    }

def default_server_args() -> dict[str, str]:
    global global_poll_mode
    return {
        "poll-mode": global_poll_mode,
        "password": PASSWORD,
        "tun-ipv4": f"{SERVER_TUN_IP}/24",
        "tun-name": "i405-server-tun",
    }

def run_command(command: list[str], check: bool = True, capture_output: bool = False, text=False, **kwargs):
    """Helper to run shell commands."""
    print(f"Running: {shlex.join(command)}")
    try:
        result = subprocess.run(command, check=check, capture_output=capture_output, text=text, **kwargs)
        if capture_output:
            print("Stdout:\n", result.stdout)
            print("Stderr:\n", result.stderr)
        return result
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error running {shlex.join(command)}, output: {e.output}") from e

def run_command_ns(namespace: str, command: list[str], check: bool = True, capture_output: bool = False, text: bool = False, **kwargs: Any) -> subprocess.CompletedProcess:
    """Helper to run shell commands within a network namespace."""
    ns_command: list[str] = ["ip", "netns", "exec", namespace] + command
    return run_command(ns_command, check=check, capture_output=capture_output, text=text, **kwargs)

def cleanup() -> None:
    """Clean up network namespaces and interfaces."""
    shutdown(*all_popens)
    print("Cleaning up network configuration...")
    # Use stderr=subprocess.DEVNULL to suppress "Cannot remove..." errors if they don't exist
    run_command(["ip", "netns", "del", SERVER_NS], check=False, stderr=subprocess.DEVNULL)
    run_command(["ip", "netns", "del", CLIENT_NS], check=False, stderr=subprocess.DEVNULL)
    # Veth pairs in the bridge namespace are automatically cleaned up when the namespace is deleted.
    print("Cleanup complete.")

def dict_to_args(d: dict[str, str]) -> list[str]:
    result: list[str] = []
    for key, value in d.items():
        result.append(f"--{key}")
        result.append(value)
    return result

def launch_client(**cli_overrides: str) -> subprocess.Popen[bytes]:
    global all_popens
    args = dict_to_args(default_client_args() | cli_overrides)
    cli = ["ip", "netns", "exec", CLIENT_NS, I405_BINARY_PATH, "client", *args]
    print(f"Launching client: {shlex.join(cli)}")
    result = subprocess.Popen(cli, env=I405_ENV)
    all_popens.append(result)
    return result

def launch_server(**cli_overrides: str) -> subprocess.Popen[bytes]:
    global all_popens
    args = dict_to_args(default_server_args() | cli_overrides)
    cli = ["ip", "netns", "exec", SERVER_NS, I405_BINARY_PATH, "server", *args]
    print(f"Launching server: {shlex.join(cli)}")
    result = subprocess.Popen(cli, env=I405_ENV)
    all_popens.append(result)
    return result

def shutdown(*popens: subprocess.Popen):
    for popen in popens:
        if popen.poll() is None:
            print(f"SIGTERM i405 instance w/ pid {popen.pid}")
            popen.terminate()
            time.sleep(0.25)
            if popen.poll() is None:
                print(f"Pid {popen.pid} did not exit cleanly, sending SIGKILL")
                popen.kill()

def assert_ping():
    """
    Send two pings over the tunnel, pass if both succeed and take the expected amount of time (not
    too slow, not too fast)
    """
    ping_cmd = ["ping", "-c1", "-w1", SERVER_TUN_IP]
    first_ping_result = run_command_ns(CLIENT_NS, ping_cmd, capture_output=True, text=True)
    second_ping_result = run_command_ns(CLIENT_NS, ping_cmd, capture_output=True, text=True)
    ping_times_ms: list[float] = []
    for ping_result in first_ping_result, second_ping_result:
        match = re.search(r"time=(\d+\.?\d+)\s*ms", ping_result.stdout)
        if match:
            ping_times_ms.append(float(match.group(1)))
        else:
            raise RuntimeError(f"Could not extract ping time from output: {ping_result.stdout}")

    longest_ping_time = max(*ping_times_ms)
    # TODO there ight be a plausible reason for it to be shorter than the min here
    assert PACKET_INTERVAL_MS / 2 <= longest_ping_time <= PACKET_INTERVAL_MS * 3, f"Ping time out of range: {longest_ping_time}"

def setup_network() -> None:
    print("Setting up netns-es and veths")

    # Create Network Namespaces
    run_command(["ip", "netns", "add", SERVER_NS])
    run_command(["ip", "netns", "add", CLIENT_NS])

    # Configure loopback interface in each namespace
    run_command_ns(SERVER_NS, ["ip", "link", "set", "dev", "lo", "up"])
    run_command_ns(CLIENT_NS, ["ip", "link", "set", "dev", "lo", "up"])

    # Create and Configure Veth Pairs for Server NS
    run_command(["ip", "link", "add", "name", CLIENT_VETH, "type", "veth", "peer", "name", SERVER_VETH])
    run_command(["ip", "link", "set", CLIENT_VETH, "netns", CLIENT_NS])
    run_command(["ip", "link", "set", SERVER_VETH, "netns", SERVER_NS])
    run_command_ns(SERVER_NS, ["ip", "addr", "add", f"{SERVER_VETH_IP}/24", "dev", SERVER_VETH])
    run_command_ns(SERVER_NS, ["ip", "link", "set", "dev", SERVER_VETH, "up"])
    run_command_ns(CLIENT_NS, ["ip", "addr", "add", f"{CLIENT_VETH_IP}/24", "dev", CLIENT_VETH])
    run_command_ns(CLIENT_NS, ["ip", "link", "set", "dev", CLIENT_VETH, "up"])

    print("Network namespaces set up")

def main() -> None:
    global global_poll_mode

    # Ensure we are running as root
    if os.geteuid() != 0:
        print("Please run this script with sudo.")
        sys.exit(1)


    # Register cleanup on exit signals
    signal.signal(signal.SIGINT, lambda sig, frame: (cleanup(), sys.exit(1)))
    signal.signal(signal.SIGTERM, lambda sig, frame: (cleanup(), sys.exit(1)))

    try:
        cleanup() # Ensure a clean state before starting
        setup_network()

        for global_poll_mode in "sleepy", "spinny":
            print(f"About to test in poll-mode: {global_poll_mode}")
            basic_test()
            reconnect_test()

        print()
        print("End-to-end test completed without error.")
        print()

    finally:
        cleanup() # Always clean up network namespaces and interfaces

def basic_test():
    print("Basic test")
    server = launch_server()
    client = launch_client()
    time.sleep(0.25)
    assert_ping()

    shutdown(client, server)

def reconnect_test():
    """Can both sides reconnect to the other after a disconnection?"""
    print("Reconnect test")
    server = launch_server()
    client = launch_client()
    time.sleep(0.25)
    assert_ping()
    shutdown(client)
    client = launch_client()
    time.sleep(0.25)
    assert_ping()
    shutdown(server)
    server = launch_server()
    # will have to increase this:
    time.sleep(1.25)
    assert_ping()

    shutdown(client, server)

if __name__ == "__main__":
    main()
