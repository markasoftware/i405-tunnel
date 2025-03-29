# I405 Tunnel: Constant-Traffic padded and encrypted tunnel

If you *really* want to make sure people can't inspect your network traffic, this tunnel is for you.
It completely hides network traffic metadata by sending packets whose sizes and timings are chosen
without knowledge of the data being sent. When data needs to be sent through the tunnel, each packet
is padded to the predetermined size and encrypted with DTLS.

## TUN vs TCP mode

I405-tunnel can run in TUN or TCP mode. In TUN mode, I405 creates a TUN network interface which you
can route traffic through. The IP packets sent to the TUN interface are padded, encrypted, and
wrapped in UDP to send to the remote. In TCP mode, a single TCP connection is opened across the
network, and a local SOCKS5 endpoint is exposed. All connections to the SOCKS5 endpoint are
multiplexed over the single TCP connection (with padding and encryption, of course), and then demultiplexed on the other side.

**TUN advantages**

+ Traffic is truly uniform. In TCP mode, we try to send `write`s in such a way that each one turns
  into a single physical network packet that can be sent immediately, but the OS has liberty to not
  do what we tell it to do; TCP is stream-oriented, not packet-oriented.

  For example, if a TCP packet is dropped, the OS will automatically handle the process of resending
  it, which happens outside the purview of I405 and hence won't match the uniform timing we aim for.

  More commonly, the OS will be constantly sending ACK packets back to the other side, outside of
  I405.

  That being said, even though the OS will be sending control packets outside of I405, the OS has no
  knowledge of the cleartext content being sent, so these control packets are completely
  uncorrelated with the cleartext content.

  HOWEVER, by seeing the TCP control traffic, an observer can easily determine when you experience
  packet drops. If an observer is trying to correlate you to some activity elsewhere, they may be
  able to match up the packet drop with a simultaneous gap in whatever you're doing through the
  tunnel. With TUN/UDP, an observer cannot definitively say you're dropped a packet (unless you drop
  a whole bunch), because all TCP acks and retransmissions are inside the padded and timed UDP
  packets. While DTLS does have sequence numbers on each packet, in DTLSv1.3 (which is the only UDP
  encryption supported by I405) the sequence numbers are encrypted.
+ Sending *all* system traffic through the tunnel is easier to set up than in TCP mode.

**TCP advantages**

+ Can be set up without root. In order to set up a TUN interface on Linux for the first time, you
  need root (or the `CAP_NET_ADMIN` Linux capability), though after initial setup it can run without
  root.
+ Easier to set up and configure; no network devices to create, no firewall rules to set up, no
  sysctl config changes, etc are needed. Configuring an application to use the tunnel is as easy as
  changing its proxy settings.
+ May have better performance.
  - Dropped packets are detected and can be retransmitted by the OS immediately, rather than needing
    to potentially wait behind lots of other packets for a proper spot in the queue, as in TUN mode.
  - Terminating TCP at a proxy node generally has a lot of potential benefits, because buffering,
    retries, etc are done independently on both sides of the proxy.
