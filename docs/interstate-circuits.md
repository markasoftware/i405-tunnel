# Interstate Circuits: Theory

I405 can be used as an alternative to Tor for anonymously accessing the Internet. However, it's not
plug-and-play like Tor; you have to set up the circuit yourself, an involved and time-consuming
process.

![Diagram of an Interstate Circuit](interstate-circuit.png)

An Interstate Circuit consists of (at least) three network hops:
1. An I405 constant-traffic connection between your home internet and the "guard" server (green in
   the diagram)
2. A connection between the "guard" server and the "exit" server (purple in the diagram). You must
   have prior knowledge that this connection cannot be monitored by your adversaries. Eg, if you're
   trying to hide from Western governments, you might choose this hop to be between two servers in
   Russia (as pictured in the diagram); conversely, if you're trying to hide from the Russian
   government, you should make this hop between two servers in the Western world.

   This step is the "catch" in how Interstate Circuits are resistant to global passive adversaries:
   An Interstate Circuit isn't safe against a truly global passive adversary that monitors *all*
   network traffic; you have to be able to make a network hop somewhere that they your adversary
   can't monitor.

   For reasons I'll explain below, I recommend running a remote desktop on the "guard" server rather
   than directly tunnelling network traffic.
3. The final egress hop from your "exit" server to the final clearnet site you're connecting to
   (orange in the diagram). The exit node can run a simple layer-3 VPN or layer-4 proxy protocol (eg
   SOCKS5).

The attacker you're hiding from will be able to observe hops 1 and 3, but not 2. Because hops 1 and
3 involve disjoint sets of IP addresses, there's no trivial way to correlate the links based on
source/destination IPs. And since hop 1 has completely uniform I405 network traffic, it's hard to
correlate with the hop 3 traffic.

Unfortunately, if you simply proxy or tunnel network traffic all the way through your Interstate
Circuit, there are some techniques an adversary could use to correlate hops 1 and 3 by inspecting
network traffic; for this reason, I recommend running a remote desktop server or other "layer-7
proxy" on the guard node rather than forwarding network traffic all the way through the circuit;
read on for details.

## Correlation attacks between hops 1 and 3

I405 is designed so that the cleartext tunneled traffic does not affect the traffic visible to
adversaries on hop 1. However, if you forward raw network packets all the way through the circuit,
an observer monitoring both hops 1 and 3 can use subtle techniques to correlate the two hops. I'm
going to explain how, and then recommend that you **do not an Interstate Circuit to forward raw
end-to-end network traffic**. Instead, I'll recommend using a "layer-7 proxy", such as a remote
desktop server, on the guard node to help decorrelate the hop 1 and hop 3 traffic.

The rest of this section is optional reading if you want to learn the details of how hop 1 and 3
traffic might be correlated.

### Maximum speed

The easiest thing the attacker can do is monitor the maximum download or upload speed you achieve on
hop 3, and can use that to make an accurate estimate of what your configured I405 speed on hop 1 is,
narrowing down the list of possible I405 connections on the internet that might belong to you.

**Possible Solution (not implemented): Artificial "inner" speed limit**. A CLI option in I405 could
artificially limit the maximum speed allowed inside the tunnel to be less than the bandwidth used by
the outer I405 packets. Then, an attacker observing the maximum speed on hop 3 would only learn that
the hop 1 bandwidth must be *higher* than the hop 3 bandwidth, but not exactly what the outer hop 1
bandwidth is.

### Inter-packet intervals

An attacker might be able to correlate traffic between hops 1 and 3 by analyzing inter-packet
intervals. For example, if you have I405 configured to send a packet on average every 27
milliseconds, and the average hop 3 packet intervals are also 27ms, the attacker can figure out
what's up.

<img src="./interval-correlation.svg" height=400>

(Note that in practice I405 applies jitter to inter-packet intervals, so it wouldn't be exactly 27ms
between each sent I405 packet. However, the *average* inter-packet interval will remain the same,
even over a long period of time)

**Possible Solution (not implemented): Scheduled Packets**. When I405 receives an IP packet to
tunnel, attach a "scheduled dispatch timestamp" of `system_timestamp() + 500ms` (where 500ms is an
overestimate of the network latency) to the packet. On the other side of the I405 connection, wait
until the scheduled timestamp to send the tunneled IP packet. The inter-packet intervals of the
tunneled IP packets when they leave the I405 tunnel will be the same as the inter-packet intervals
when those packets entered the tunnel, completely independently of the inter-packet intervals of the
encrypted I405 packets.

### Dropped packets

The more insidious way to correlate hops 1 and 3: If a packet is dropped on hop 1 while traffic is
actively being tunneled, packets will be dropped on hop 3. Packet drops are normal and fairly common
over the internet; the adversary does not need to actually cause the packet drops. An adversary will
be able to tell that a packet was dropped on hop 1 because the inter-packet interval was larger than
usual, and on hop 3, by noticing a gap in TCP sequence numbers. When the adversary notices drops on
hops 1 and 3 at almost the same time, they become more confident that these two hops are part of the
same Interstate Circuit.

<img src="./drop-correlation.svg" height=400>

**Possible Solutions (not implemented)**:
+ **Forward error correction**: Use error correction on hop 1 so that even if a packet is dropped on hop 1, I405 is able to
fully reconstruct the tunneled traffic and avoid dropping packets on hop 3. But this isn't perfect:
Any error correction algorithm will only be able to handle a finite amount of consecutive dropped
packets. And on the internet, packet drops tend to be correlated: You might not drop any packets for
minutes or hours, and then suddenly drop dozens of packets in a row, if a buffer somewhere in the
network gets full, or a router goes down and routes aren't updated immediately. The amount of error
correction needed to reliably correct most packet drop events would be quite high, increasing
latency and bandwidth overhead.
+ **Eager retransmissions**: Use any spare space in each I405 packet to retransmit un-acked messages, even though they're probably not dropped. This is especially useful in the outbound (home->internet) direction because outbound traffic usually consists of small, isolated HTTP requests, leaving lots of room for retransmits.
+ **Multi-path** (suggested by Tobias Pulls): Instead of sending packets directly from home to guard over the internet for hop 1, set up multiple paths. There's lots of ways to do this:
  - Use different residential connections: Many packet drops are due to just the local residential network. You could bypass this by renting multiple internet connections (eg, one using fiber, and another with 5g home internet) and using both for redundancy.
  - Use different routes over the internet: You can't control how your packet will be routed over the internet, so you'd just have to split up hop 1 into shorter hops between servers you control, chosen such that the routes home->proxy 1->guard and home->proxy 2->guard overlap as little as possible to add redundancy.
+ **Faster retransmits by splitting up hop 1**: The reason we can't mitigate packet drops naively with TCP-like retransmissions is because of the scheduling feature (used to mitigate packet timing analysis, as described above): we need to set the schedule delay long enough so that it includes any retransmissions. TCP doesn't retransmit until substantially more than a full round-trip time has elapsed, which means tha the packet will not reach the server until 1.5RTT after the original send time, rather than the typical 0.5RTT. This means the scheduling delay has to be set to at least 1.5 RTT, and this scheduling delay is applied to *all* packets, not just those that are dropped.

  Retransmission can be salvaged if we split up hop 1 into many shorter, lower-latency hops: home->proxy 1->proxy 2->proxy 3->guard. If the latency on each "mini-hop" between proxies low enough, then we can retransmit between them while keeping scheduling delay reasonable.

  There's lots of variations on this theme. For example, it's common for most of the packet drops to be due to the residential network of the user. A single retransmitting proxy between home and guard, geographically near the user's residential network, is good in this case. The latency added in case of a packet drop is just the RTT between the residential network and proxy, which can be made small.

### Scheduling & FEC discussion

Dispatch scheduling fully prevents analysis based on inter-packet intervals. Error correction, retransmission, etc does *not* fully solve the (IMO more serious) problem of dropped packets, because there can always be some unrecoverable string of dropped packets.

I405 has a "packet monitor" mode which reports on packet delays and drops in either direction; see the help text for `--monitor-packets` to learn how to use it. Initial measurements indicate that packet drop rates are low enough that error correction will do a good job.

I envision someone setting up an Interstate Circuit like so:
1. Run in `--monitor-packets` mode between the home and guard nodes for a few days.
2. Analyze the packet timing and drop rates to determine a reasonable error correction level and dispatch scheduling delay (using an analysis/simulator tool inside I405)
3. Run I405, with continuous built-in monitoring for when a packet was dropped in a way that wasn't recovered by the error correction, so the user knows when their privacy is potentially compromised.

(none of this is implemented yet)

But until we have some fancy error correction and scheduling mechanisms, you're stuck with Layer 7 proxies, described below!

## Systematically defending against hop 1 - hop 3 correlation attacks: Layer-7 proxies

Layer-7 is the application layer. A "layer-7 proxy" is a proxy that proxies application-level
actions rather than proxying the network traffic made by the application.

The most general layer-7 proxy is a remote desktop server that sends video of the desktop, and
receives mouse and keyboard events. You could argue this isn't truly layer-7, since mouse and
keyboard events don't correlate 1-to-1 with application-level actions, but it's enough for our
purposes.

Hop 1 - hop 3 correlation attacks are effectively defeated by running a layer-7 proxy on the guard
node, rather than actually forwarding network traffic directly to the exit node (eg with a VPN
protocol or TCP proxy).

A layer-7 proxy defeats the packet drop correlation attack described above. If an I405 packet gets
dropped, then the application-level action will either just not occur, or will happen after a short
delay (while the application retransmits the intent to perform the action.

**Concrete example**: Let's take the process of typing a website address in the web browser address
bar and hitting enter), in the presence of packet drops.
+ In a layer-3 Interstate Circuit (eg, if you directly forward hop 1 traffic over hop 2 using
Wireguard): After hitting enter, potentially multiple megabytes of network traffic will be
transmitted from the website to your home machine over the circuit. If there's any packet drop on
hop 1 during the download, it will cause a TCP retransmission on hop 3, which will be visible to an
adversary monitoring hop 3 who can correlate the two drops.
+ In a layer-4 interstate circuit (eg, guard and exit nodes both running SOCKS5 TCP proxies): After
  hitting enter, once again, potentially multiple megabytes of network traffic will be sent from the
  remote website to your local machine. If a packet is dropped on hop 1, it won't cause a TCP
  retransmission on hop 3 because the SOCKS proxy ensures reliable delivery on each hop. However,
  the download on hop 3 will *pause* / be *delayed* for a short amount of time just after the hop 1
  packet drop.

  To understand this, realize that the hop 3 is typically much higher bandwidth than the hop 1
  connection (I405 speeds are typically set slow because of how much traffic they send). The SOCKS
  proxy on the exit node will typically be backpressured by hops 1 and 2 as a result, and will
  advertise a full TCP receive window starting shortly after the download begins. Every time a bit
  more traffic goes through the I405 hop 1 tunnel, the backpressure will be released slightly and
  the exit will advertise a little bit of space in its receive window. The receive window updates
  are visible to the adversary monitoring hop 3. If there's a packet drop on hop 1, the receive
  window will stay the same until that packet gets retransmitted. The adversary can correlate these
  delayed receyive window updates with packet drops on hop 1.
+ In a layer-7 interstate circuit (eg, a remote desktop server on the guard node, running a browser
  that then uses a SOCKS proxy running on the exit node): The website will be downloaded to the
  guard node as quickly as possible after hitting enter. Any dropped packets on hop 1 will cause the
  remote desktop video stream to be delayed or skip frames, but will not affect the hop 3 traffic of
  the download at all. So there's no correlation between drops on hop 1 and drops/delays on hop 3.

  The only packet drop that would be observable to an adversary here is if the packet that encodes
  the "enter" keypress gets dropped. In this case, the remote desktop software will retransmit the
  enter keypress, which will get performed slightly later. However, this isn't observable to the
  adversary, who doesn't know whether the keypress was delayed by a retransmit, or whether the user
  genuinely pressed the enter key a split second later than they actually did.

<!-- TODO would be good to get a diagram of this concrete example in each case -->

You can still contrive some scenarios with a layer-7 proxy where packet drops on hop 1 path will be
observable by an adversary watching hop 3. For example, take a website sends an HTTP request on
every mouse movement. If there's a packet drop on hop 1, some mouse movements may not be
transmitted, and there may be a conspicuous gap in a sequence of HTTP requests as a user moves their
mouse across the screen. Situations like these are rare, mostly contrived, and hard to exploit.

The Guard node should be running a layer-7 proxy, but the exit node can and should just run a simple
layer-3 (eg Wireshark) or layer-4 (eg SOCKS5) proxy.

### Remote desktops are laggy and a general PITA. Are there other layer-7 proxies I can use?

Here are some application-specific layer-7 proxy examples:
+ Bittorrent: Run a headless bittorrent client on the guard node (still proxying through the exit
  node. Or just run the bittorrent client on the exit node instead!), download the file you want,
  and then use `rsync`/`scp`/etc to transfer the downloaded file over hop 1 (I405) tunnel to your
  home computer.
+ Instant Messaging: Run a command-line IRC/Matrix/XMPP client on your guard node (once again, still
  proxying through the exit node to prevent trivial analysis of your network traffic based on IP
  addresses!). Control the client by SSHing from your home computer into the guard node over hop 1
  (I405).

  (For IRC specifically, you could use dedicated IRC bouncer software like ZNC)

#### What about web browsing? Are there are any good layer-7 proxies for web browsing other than a remote desktop?

For simple websites, run Lynx, a text-based browser without javascript or anything. For more complex websites, try [Browsh](https://brow.sh) or [Carbonyl](https://github.com/fathyb/carbonyl), which render Firefox and Chromium (respectively) in the terminal. Why is Firefox in the terminal any better than a low-resolution remote desktop? Because the websites text is preserved as text in the terminal; only images, layout elements, etc get severely downscaled into blocky unicode characters. This keeps the website super usable at low bandwidth. Also, if you're asking that question, you've clearly never tried to set up a low-bandwidth remote desktop on Linux. It's a HUGE pain in the ass.

Another kinda-layer-7 solution is to use [mitmproxy](https://www.mitmproxy.org/) on the guard to proxy all requests made by a browser running on the home node. Because mitmproxy decrypts https and fully buffers responses before sending them back to the client, it is effectively a proxy at the level of HTTPS requests. This isn't truly "layer 7", because HTTPS requests do not correspond to application-level actions, but it's still a lot higher level than IP or TCP and largely prevents the attacks described here.

<!-- old description:

As described earlier, forwarding raw network traffic (either at layer-3 or layer-4) over an
Interstate Circuit isn't safe. But what if we forward at the level of HTTP requests instead? That's
the idea behind HTTP proxies, but they're aren't perfect out of the box for a few reasons:
1. When browsers are configured to use an HTTP proxy to proxy HTTPS traffic, they don't actually
   send HTTP requests to the proxy; instead, they use the `CONNECT` HTTP method, which converts the
   HTTP proxy into a layer-4 TCP proxy. This is necessary so that the connection can be end-to-end
   encrypted. And as described earlier, an Interstate Circuit based on layer-4 TCP proxies is
   problematic.

   This can be solved by using a "TLS terminating HTTP proxy" that uses a self-signed certificate to
   decrypt then forward the raw HTTP request, and then buffer the response, but I can't find any
   decent open source TLS terminating proxies.
2. Even over insecure HTTP, when downloading a large file, an HTTP proxy effectively turns into a
   layer-4 TCP proxy because it won't buffer the entire downloaded file. Once the buffer (if any)
   fills up, the HTTP proxy will become backpressured by the hop 1 bandwidth. Every time a new I405
   packet is sent (from guard to home) and new packets are read from the TUN, the backpressure will
   release a little bit, and the HTTP proxy will update its TCP window to admit a bit more
   downloaded data from the destination website. Ie, the HTTP proxy is acting effectively as a
   layer-4 proxy.

   A similar problem can occur on the upload path as well.

   The solution is to have a large fixed-size buffer per request in the HTTP proxy, and to abort a
   download or upload if the total downloaded or uploaded data for the request exceeds the buffer
   size. To solve the upload case, the proxy must also not send out HTTP requests until the entire
   request is received.

It's on the roadmap to build an HTTP(S) proxy that solves the above problems! It won't be perfect
though; mainly, Real-time web communication tech like WebSockets and WebRTC, as well as long-lived
HTTP connections (Comet? Does anyone use that term anymore?) won't work at all.

There's also one remaining challenge: Malicious JavaScript can measure the hop 1 bandwidth,
inter-packet intervals, etc, even with the buffering described in point (2) above. There are some
potential heavier-weight solutions to this (like also buffering the responses on the home computer,
and only delivering them to the browser when complete). But in the shorter term, I'll just consider
malicious JavaScript outside the threat model.

-->

## Threat model of a layer-7 Interstate Circuit
A layer-7 interstate circuit constructed as recommended in this document is designed so that an
adversary with the following capabilities:
+ Read all network traffic on hops 1 and 3 (but not hop 2). (on-path, read-only)
+ Send arbirary IP traffic. (off-path, read-write)

...is unable to determine that the home and guard nodes are part of the same interstate circuit as
the hop 3 traffic and the exit node.

A layer-7 Interstate Circuit does *not* generally protect against an adversary with any of the following capabilities:
+ Block arbitrary IP traffic (on-path, read-write). A very blunt example: If you're in the middle of
  an instant messaging conversation over the Interstate Circuit, then your ISP suddenly shuts down
  your hop 1 connection, you'll be unable to continue chatting. The fact that you stopped chatting
  over hop 3 when hop 1 died is evidence that they're connected!
+ Observe hop 2 traffic.
+ Is able to take control over the guard or server nodes, beacuse then they could observe hop 2 traffic.
+ Knows that the same person (you) is in control of the guard and exit nodes (eg, if you purchase the exit node in a non-anonymous way)

I405 and Interstate Circuits are new and experimental. I recommend you read this whole document and
fully think about the security properties of an Interstate Circuit yourself before setting one up.
# Interstate Circuits: Practice
## Setting up an Interstate Circuit

1. Identify which adversaries you are trying to hide your network traffic from.
2. Find two servers you can rent, a "guard" and an "exit", which have a network link between them
   which your adversaries cannot monitor. (as a corollary, your adversaries mustn't be able to login
   to or get physical access to the servers themselves).
3. Buy the "guard" server. You need not purchase it anonymously.
4. Set up an I405 tunnel between your home network and the guard server. Call this "hop 1". See the
   [Usage](./usage.md) documentation for details on how to install and run I405.
5. Anonymously purchase the "exit" server. There are many ways to complete the purchase anonymously,
   and you'll have to be a bit creative. Here are a few ideas:
   + Complete the purchase using the already-purchased guard server as a proxy (ideally a layer-7
     proxy, as described above). This only works if the connection from the guard node to the
     website where you'll perform the purchase of the exit server, eg
     https://example-covert-vps.com, is not observable by your adversaries. You have to be careful
     of not just the website, but also eg any CDNs it uses, any analytics libraries, and the payment
     processor. If any of the connections related to your purchase are observable by an adversary,
     they may be able to link your purchase of the exit server to the guard server's IP, which can
     be linked to you.

     Realistically, very few hosting providers will meet these requirements.
   + Find a VPN or proxy service such that your guard-to-VPN connection is not observable by your
     adversary (eg, for a guard in russia, that could mean a russian VPN service). Complete the
     purchase of the exit node using this VPN.

     This is like creating a temporary Interstate Circuit. Because you're using a VPN or proxy, it's
     like a layer-3 or layer-4 Interstate Circuit instead of the recommended Layer-7 Interstate
     Circuits described earlier. However, since you're just using it once, and realistically the
     attacks on layer-3 and layer-4 Interstate Circuits are quite hard to pull off, you can probably
     get away with it.
   + Use a "task proxy", ie, someone who will purchase the server on your behalf in exchange for
     cryptocurrency. Sites like https://xmrbazaar.com have people offering task proxy services. I
     imagine lots of people on darknet forums also offer this service. Disclaimer, I've never tried
     this myself, and there are probably lots of scammers!

     Actually contacting the person who is acting as your task proxy in an anonymous manner is
     difficult.
   + Complete the purchase using [Nym](https://nym.com). Nym is the only large-scale operating
     mixnet, and is the only anonymous networking tool I'd recommend other than an Interstate
     Circuit (though it has its own problems; see the
     [comparison](./onion-mixnet-interstate-comparison.md)).
6. Set up a layer-7 proxy (probably a remote desktop server) on the guard node. If your choice of
   layer-7 proxy is in fact a remote desktop, the three I can recommend for Linux are:
   + XRDP is generally easiest to set up and has acceptable performance.
   + Sunshine/Moonlight are meant for game streaming but work great for everyday applications too.
     Moonlight is smoother and faster than any other remote desktop software I've tried, but lacks
     typical remote-desktop features like clipboard and file sync. Bandwidth is also fairly high.

     Make sure to configure the client (sunshine) to use a bandwidth less than the I405 connection's
     bandwidth, otherwise it gets really nasty.
   + NoMachine. It's nonfree software, but is certainly the best of these three at conserving
     bandwidth and feels faster than XRDP.
7. Configure the guard node so that it can't communicate except over hops 1 and 2. If your guard
   node makes any sensitive connections to the internet that are visible by your adversaries, you're
   screwed. You can do this eg by configuring the firewall to only allow connections to/from your
   home IP and the exit server IP.
8. For whatever layer-7 proxy you set up, configure it so that it communicates over the exit server
   before accessing the clearnet.

   For the common case of a remote-desktop server with a web browser running inside, one option is
   to configure the web browser to use a SOCKS5 proxy server running on the exit node (I recommend
   `microsocks` or `gost`. With `gost` in particular, you can reduce the latency of opening new TCP
   connections by actually setting up a QUIC connection on hop 2 that can multiplex multiple TCP
   connections).

I hope to start collecting information on what server providers in Russia and other
non-Western-friendly countries are easier to purchase and work well as guard or exit nodes. I'd also
love to provide containers or scripts to easily set up the guard and exit servers with the correct
networking, because it's a little tricky if you're not a networking guy/gal.

There's a lot of information on this page. Please let me know which parts of it are confusing to you
so I can improve the documentation!
