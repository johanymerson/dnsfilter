# DNS filter module for Unbound
This Unbound module allow the use of OpenDNS or similar DNS filters while
still doing the actual resolving of domains using Unbound.
This allow the use of DNSSEC while still using OpenDNS for filtering,
and also avoids issues with GeoDNS.

The script is primarily for use with OpenDNS, but should be easy to modify
for other DNS filters such as Comodo or Norton.

# Configuration of Unbound
The following options should be added to the server section of unbound.conf:
```
server:
	module-config: "validator python iterator"
	chroot: ""
```

Then add a python section:
```
python:
	python-script: "/path/to/dnsfilter.py"
```

If you wish to see the OpenDNS block page for blocked sites, you will also need:
```
forward-zone:
        name: "opendns.com"
        forward-addr: 208.67.222.222
        forward-addr: 208.67.220.220
```