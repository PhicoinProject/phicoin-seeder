# Phicoin Seeder

Phicoin-seeder is a crawler for the Phicoin network, which exposes a list
of reliable nodes via a built-in DNS server.

Features:
* Regularly revisits known nodes to check their availability
* Bans nodes after enough failures, or bad behaviour
* Accepts nodes with version 80000 and above to request new IP addresses from,
  and only reports good nodes with version 80000 and above.
* Keeps statistics over (exponential) windows of 2 hours, 8 hours,
  1 day and 1 week, to base decisions on.
* Very low memory (a few tens of megabytes) and cpu requirements.
* Crawlers run in parallel (by default 96 threads simultaneously).

## REQUIREMENTS

$ sudo apt-get install build-essential libboost-all-dev libssl-dev

## USAGE

Assuming you want to run a dns seed on dnsseed.example.com, you will
need an authorative NS record in example.com's domain record, pointing
to for example phiseed.example.com:

$ dig -t NS dnsseed.example.com

On the system phiseed.example.com, you can now run dnsseed:

$ ./dnsseed -h dnsseed.example.com -n phiseed.example.com

If you want the DNS server to report SOA records, please provide an
e-mailaddress (with the @ part replaced by .) using -m.

## COMPILING
Compiling will require boost and ssl.  On debian systems, these are provided by `libboost-dev` and `libssl-dev` respectively.

$ make

This will produce the `dnsseed` binary.

## RUNNING AS NON-ROOT

Typically, you'll need root privileges to listen to port 53 (name service).

One solution is using an iptables rule (Linux only) to redirect it to
a non-privileged port:

$ iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353

If properly configured, this will allow you to run dnsseed in userspace, using
the -p 5353 option.

Another solution is allowing a binary to bind to ports < 1024 with setcap:

$ setcap 'cap_net_bind_service=+ep' /path/to/dnsseed

## PHICOIN NETWORK PARAMETERS

The seeder is configured for the Phicoin network with the following parameters:
- Main network port: 28964
- Test network port: 18965
- Regtest network port: 18966
- Network magic bytes: PHIX (0x50, 0x48, 0x49, 0x58)
- DNS seeds: seed1.phicoin.net through seed6.phicoin.net

## LICENSE

See COPYING for license information. 