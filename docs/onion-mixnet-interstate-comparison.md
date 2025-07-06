# Onion Routing vs Mixnet vs Interstate Circuit comparison

Tor and I2P, the most popular real-world network anonymity softwares, are both Onion Routers. They
send packets through a few (typically 3) volunteer-run servers, forwarding each packet to the next
server as quickly as they can. As a result, an adversary who can monitor the "entry" and "exit" hops
into and out of the Tor or I2P networks can fairly easily perform timing analysis to figure out
which entries correspond to which exits and deanonymize users. Tor was never designed to protect
against such "global passive adversaries".

Mixnets are more robust.

Overview of pros/cons of each type of anonymity network, followed by more in-depth descriptions of each category:

|                                         | Onion Routing (Tor/I2P) | Mixnet (Loopix/Nym) | Mixnet (Synchronous) | Interstate Circuit |
|-----------------------------------------|-------------------------|---------------------|----------------------|--------------------|
| Low-latency                             | ✅                      | 🟡                  | ❌                   | ✅                 |
| Easy to setup                           | ✅                      | ✅                  | ✅                   | ❌                 |
| Free as in beer                         | ✅                      | ❌                  | 🟡                   | ❌                 |
| Resistant to global passive adversaries | ❌                      | ✅                  | ✅                   | ✅                 |
| Resistant to global active adversaries  | ❌                      | 🟡                  | 🟡                   | 🟡                 |
| Resistant to sybil attacks              | ❌                      | ❌                  | ❌                   | ✅                 |
| Ready for practical use                 | ✅                      | 🟡                  | ❌                   | ✅                 |
| Implementation lines of code            | >100,000                | >100,000            | N/A                  | <10,000            |

## Low-latency

"low-latency" here means low enough latency to be suitable for web browsing, so ideally <1 second round-trip.

+ Onion routers forward messages as soon as they arrive, so have the lowest theoretical latency,
  basically just being the network latency between the nodes.
+ Results from the original Loopix paper indicate that in a reasonably busy network, only a few
  milliseconds of added latency at each hop will suffice. However, docs on the Nym website explain
  that latencies are typically greater than 1 second; I'm not sure why. <!-- TODO include graph from that Nym paper explaining latencies in multiple seconds -->
+ Synchronous mixnets have to wait for a whole bunch of messages to be collected before forwarding
  them on, which typically adds at least seconds of latency. With some designs, this latency may be
  small enough to be suitable for clearnet web browsing.
+ I405 will forward messages with just a few milliseconds of added latency when configured for
  fairly high bandwidth (the amount of time to wait for the next pre-scheduled packet to be sent).

## Easy to set up

Using Tor is as simple as downloading and using the Tor Browser, which has a UI that's familiar to
non-technical users. Nym requires acquiring and spending a cryptocurrency token with a special
client, making it harder to set up than Tor but still not bad. There aren't any other widespread
mixnet implementations, but they all theoretically could be as simple to use as Tor.

An Interstate Circuit, on the other hand, requires carefully selecting, purchasing, and setting up
custom servers from overseas providers, whose legitimacy may be hard to verify, and who may not even
speak your lanugage. See [Interstate Circuits](./interstate-circuits.md) for details.

## Free as in beer

Tor nodes are (at least ostensibly) run by volunteers and non-profit organizations. Since Tor is
fairly efficient and has minimal cover traffic, a volunteer network is practical.

On the other hand, Loopix and I405 both send traffic at a predetermined rate equal to the maximum
supported transmission rate. This means sending orders of magnitude more traffic than Tor would,
which is impractical for a volunteer-run network. In an Interstate Circuit, you pay for your
bandwidth by renting your own servers to run nodes on. In Loopix/Nym, you pay node operators using a
custom cryptocurrency.

Proposed synchronous mixnets typically do not discuss employing fixed-rate cover traffic like
Loopix, and hence could be used with a volunteer network. But there's no reason why a synchronous
mixnet with fixed cover traffic couldn't exist, and such a network wouldn't be feasible with a
volunteer network either.

## Resistant to Global Passive Adversaries

Onion routers are extremely susceptible to end-to-end traffic correlation attacks. The most
convincing argument I've read is "[Sampled Traffic Analysis by Internet-Level
Adversaries](https://murdoch.is/papers/pet07ixanalysis.pdf)". The paper describes how an adversary
sampling only a small fraction of packets at strategically chosen locations could deanonymize Tor
users who download only a few megabytes of data. Other papers include "[Traffic Correlation on Tor
by Realistic Adversaries](https://apps.dtic.mil/sti/pdfs/ADA602282.pdf)", and "[Timing analysis in
low-latency mix networks: attacks and
defenses](https://www.cs.utexas.edu/~shmat/shmat_esorics06.pdf)".

Loopix makes a good argument that they're resistant against read-only global passive adversaries by
employing fixed-rate cover traffic (somewhat similarly to I405!) and a number of other techniques.

Many other proposed mixnets do not employ constant-bitrate cover traffic, but there's no reason why
that feature couldn't be added, so I consider them resistant to "GPAs" also.

Interstate Circuits are resistant to GPAs as long as you are able to make a single, chosen network
link that is not observable by the adversaries you are worried about. Read more on the main page:
[Interstate Circuits](./interstate-circuits.md).

## Resistant to Global Active Adversaries

No low-latency anonymity network can be fully protected against an active adversary who can block
arbitrary network traffic. At the bluntest level, an adversary can suddenly block the connection
that you are using to connect into the anonymity network, and then observe flows of traffic leaving
the network that also cease shortly afterwards.

However, such attacks might be too obvious so there's still some value in trying to prevent attacks
against global adversaries that drop, corrupt, or spoof smaller numbers of packets.

Any layer-3 (IP) or layer-4 (TCP) anonymity network is necessarily going to be vulnerable to
correlation attacks by adversaries who can cause packets to be dropped on the link that connects the
user into the anonymity network. A dropped packet on the entry link into the network will result in
either dropped or delayed packets at the link where that packet was supposed to leave the anonymity
network and go back into the clearnet. In a layer-3 tunnel, dropped packets at the network entry
will cause dropped packets at the network exit. In a layer-4 proxy, dropped packets at the network
entry will cause retransmissions and delay the packets at network exit.

If you set up an Interstate Circuit based on layer-3 or layer-4 tunnels (not recommended), then it
is vulnerable to correlation attacks based on packet drops as well. If you set up an Interstate
Circuit as a layer-7 (application layer) proxy, eg by connecting to a remote desktop server on the
guard node rather than actually making network connections to your ultimate clearnet destination
through the tunnel, packet-drop-based correlation attacks become much harder.

## Resistant to Sybil Attacks

If an adversary controls any significant portion of an onion routing network (doesn't need to be 51%
or even close to it), then some portion of circuits will, by chance, have all their hops be through
nodes run by the adversary. The adversary can trivially deanonymize users who are unlucky enough to
make such circuits.

Loopix makes some claims about being resistant to Sybil attacks, but only in a very narrow sense of
being resistant to sybil "users". It is still vulnerable to sybil attacks on the mixnet nodes. Nym
sets up some barriers so that you can't just spin up thousands of mixnet nodes overnight, but a
dedicated attacker can absolutely perform an undetected sybil attack on Nym with a moderate amount
of money and time.

In Loopix and other mixnets, an adversary controlling a substantial portion of the mixnet nodes will
occasionally, by chance, happen to control all the nodes for the paths that certain packets take,
and can trivially deanonymize the users of such packets. TODO read more carefully how Loopix tries
to prevent this, maybe thanks to the providers hiding identity of their users?

## Ready for practical use

Tor and I2P have been used in practice for well over a decade and have healthy networks of volunteer
nodes. Nym's mixnet has been running since 2022 (I think? It's hard to tell if it was fully
operational yet). However, it's unclear if there are enough users and mixnet nodes right now for it
to be very anonymous.

Most other mixnets never went beyond academic papers. Many have functional implementations that were
used in the papers for evaluation purposes, but that's it. None have large enough P2P networks to be
really anonymous.

The I405 software is not particularly mature, but no large P2P network is necessary for it to
achieve its anonymity properties, so I consider it ready to use. (This is a bit misleading -- an
adversary monitoring "hop 3" of an Interstate Circuit might be able to tell that the traffic
originated from *an* interstate circuit, even if they don't know exactly which one, dependeng on how
you set up the circuit. In this case, you would want there to be lots of I405 tunnels in production
to increase the anonymity set. But if you set up an Interstate Circuit as recommended [in the
docs](./interstate-circuit.md) using a remote desktop on the "guard" node, this shouldn't be a
concern).

## Implementation lines of code

I405 is much simpler than Tor, I2P, or Nym, so its codebase is much smaller and easier to audit and
understand. Interstate Circuits are also easier to understand for a human than Loopix-like mixnets.
