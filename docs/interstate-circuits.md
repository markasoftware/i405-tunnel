I405 can be used as an alternative to Tor for anonymously accessing clearnet sites.

TODO diagram

An Interstate Circuit consists of (at least) three network hops:
1. An I405 fully padded connection between your home internet and the "guard" server
2. A connection between the "guard" server and the "exit" server. You must have prior knowledge that
   this connection cannot be monitored by whoever you're hiding from. Eg, if you're trying to hide
   from Western governments, you might choose this hop to be between two servers in Russia;
   conversely, if you're trying to hide from the Russian government, you should make this hop
   between two servers in the Western world.
3. The final egress hop from your "exit" server to the final clearnet site you're connecting to.

The attacker you're hiding from will be able to observe hops 1 and 3, but not 2. Because hops 1 and
3 do not involve the same servers, the attacker will not be able to simply use IP addresses to
correlate them. Furthermore, the observable network traffic on hop 1 is uniform and uncorrelated to
the actual data being tunnelled, so the attacker cannot determine that the traffic on hops 1 and 3
are correlated with any amount of statistical analysis.

An attacker might be able to correlate the time between packets ("packet intervals") between hops 1
and 3. For example, if your tunnel sends a packet every 27 milliseconds, and the hop 3 packet
intervals are always approximately multiples of 27ms, the attacker might know what's up. I405 has
a robust "scheduling" protection against this attack, at the cost of latency.

Note that a dedicated attacker who observes hop 3 can still probably determine the following:
1. The traffic on hop 3 was tunneled through I405 at some point before reaching the clearnet.
2. The I405 tunnel has at least as much bandwidth as the maximum observed transfer speed on hop 3.
3. The I405 tunnel has latency no greater than the lowest observed latency on hop 3.

Here's an incomplete list of the things the attacker *cannot* determine:
1. Which websites you (where "you" means your real-world identity, or home residential IP) are
   connecting to.
2. When you are accessing websites.
3. How much data you are sending to/from websites (beyond the maximum cap dictated by the bandwidth
   set in your I405 configuration)

Tor advantages / Interstate Circuit disadvantages:
+ Tor is mostly plug-and-play; an Interstate Circuit requires careful setup.
+ Censorship resistance: With appropriate bridges, Tor can be used to bypass an ISP or government
  that is trying to block you from using Tor. I405 makes no effort to hide the fact that I405 is
  being used (on hop 1).
+ Tor is free to get started with; An I405 circuit requires you to rent 2 servers, and at least one
  of them must be paid for anonymously, probably using a privacy-oriented cryptocurrency.
+ Tor will often have lower latency than an I405 circuit with generous "scheduling latency" (see
  section on scheduling TODO).
+ I405 has massive bandwidth overhead and it's easy to waste terabytes of bandwidth per month on
  cover traffic. Tor is more efficient.
+ I405 works best when running 24/7, while Tor is intended to just be turned on when you need it.
  This means whatever PC in your home is running I405 should always be on.

I405 Circuit advantages / Tor disadvantages:
+ Immune to "global passive adversaries" (as long as you can make one network hop that's unmonitored
  by the adversaries you're worried about, see above). This is the entire point of using an I405
  circuit.
+ Immune to sybil attacks, where an attacker controls a large portion of nodes in a volunteer-run
  network, because I405 is not a volunteer-run network. (TODO link sybil) Many suspect that the NSA
  and other governments control large numbers of Tor nodes. If an attacker happens to control all
  three hops in a Tor circuit, you're instantly deanonymized. By chance, this is likely to happen if
  you use Tor often.
+ More reliable and consistent network performance, since you control all the servers in the circuit
  rather than relying on a peer-to-peer network.
+ Potentially higher maximum bandwidth, depending on configuration.
+ Choose your exit IP address (because you buy your own exit server), while Tor exit node IPs are
  publicly known and blocked on many websites.

To set up an I405 circuit, you must:

1. Identify which attackers you are trying to hide your network traffic from.
2. Find two servers you can rent, a "guard" and an "exit", which have a network link between them
   which your set of attackers cannot monitor. (as a corollary, your attackers mustn't be able to
   login to or get physical access to the servers themselves).
3. Buy the "guard" server. You need not do this anonymously.
4. Set up an I405 tunnel from your home network to the guard server. Call this "hop 1"
5. Anonymously purchase the "exit" server. There are many ways to do this. Here's one method,
   assuming your exit server provider has a simple clearnet web store at
   https://example-covert-vps.com :
   + Ensure that the internet connection between your guard server and
     https://example-covert-vps.com is not able to be monitored by your attackers. For example, if
     your attackers are the "five eyes" governments, then you'd want both your guard server and
     https://example-covert-vps.com to be Russian websites with routing between them staying
     entirely within Russia.
   + Anonymously pay for the exit server using an anonymous cryptocurrency, such as ZCash. Ensuring
     that your IP is not associated with the transaction may be difficult. If the server provider
     has a self-hosted payment gateway, then you may be able to trust that no information about
     transactions used to pay for servers there will ever be revealed, and then you can pay for the
     server even using your home internet. On the other hand, if the server provider uses a
     third-party cryptocurrency payment processor, then your attackers may learn the details of your
     transaction. You cannot safely broadcast the transaction from your guard node, because your
     attackers know your guard node IP. One option which could work for Monero, because Monero nodes
     have publicly accessible RPC interfaces, is to find a Monero node that has a route from your
     guard node which is not traceable by your attackers. (Eg, if Western governments are your
     attackers, and your guard node is in Russia, then find a Monero node in Russia). Then, you can
     use the RPC interface of that node to broadcast your transaction.

     In general, anonymous payments are tricky. Be creative in finding a way to hide your IP to send
     the transaction. Honestly, just going to a coffee shop in a city you don't visit often, and
     then also using Tor, is probably sufficient protection.

     I'm not super familiar with the anonymous cryptocurrency landscape, so there may be simpler
     options than what I've presented here.
6. Configure your guard and exit servers such that you can send traffic from your home network, over
   the I405 tunnel to the guard, over any sort of tunnel (eg wireguard, or even just GRE) to the
   exit, and then to arbitrary clearnet destinations from the exit.

   One way to do this is to run a Wireguard proxy between the guard and the exit, and configure the
   routing table on your guard and exit such that all traffic received over I405 on the guard gets
   routed over the Wireguard tunnel to the exit. Then use SNAT on the exit to send the tunneled
   traffic to the clearnet and back.

   Important: When configuring your exit server, you must only connect to it (eg over SSH) via the
   I405 tunnel you already created through the guard. This way, your attackers never learn that you
   operate the exit.

So yeah, it's not that easy. I hope to start collecting information on what server providers in
Russia and other non-Western-friendly countries are easier and harder to use. I'd also love to
provide containers or scripts to easily set up the guard and exit servers with the correct
networking, because it's a little tricky if you're not a networking guy/gal.
