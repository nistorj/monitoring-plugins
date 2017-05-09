# monitoring-plugins

Summary
-------

These monitoring plugins was designed to work with compatible NMS systems and utlize the Monitoring::Plugin modules in Perl.  Some examples are Icinga, Naemon, Nagios, and Shinken to name a few.  Each plugin has it's own documentation section below.


General Requirements
--------------------
These monitoring tools are based on perl.  Some monitoring systems support embedded perl interpreter and some execute the perl each run.  Information about the perl modules required are listed per script.



## check_bgp: BGP

#### Perl Modules
 Monitoring::Plugin, Net::IP, Net::SNMP, Socket


#### Vendor Support
The following has been verified to be working based on recent equipment and recent code.
* Arista
* Brocade
* Cisco
* Juniper
* Generic BGP4-MIB (RFC4273) support

#### Installation

=== Work in progress ===

#### Configuration

There are a few variables which can be used tweaked for the different environments.

The peerip variable supports both IPv4 and IPv6 address notation.  An error is returned if the address is invalid.
```
 vars.bgp_peerip = "<value>"
```


#### Configuration Examples


Example 1: IPv4 peer, auto-detect router type.
```
object Service "BGP-Uplink" {
	import           = "template-default-import"
	host_name        = "router1.example.ca"
	check_command    = "bgp"

	vars.bgp_peerip	 = "10.2.3.4"
	vars.bgp_snmpcom = "c0mmun1ty"
	vars.bgp_snmpver = 2
}
```

Example 2: IPv6 peer, auto-detect router type and warn if prefix count is below 25000, crit if below 22000
```
object Service "BGP-Peer-A" {
	import           = "template-default-import"
	host_name        = "router2.example.ca"
	check_command    = "bgp"

	vars.bgp_peerip  = "fd9d:4c91:360a::21"
	vars.bgp_snmpcom = "c0mmun1ty"
	vars.bgp_snmpver = 2

	vars.bgp_pfxlow  = true
	vars.bgp_warn    = 25000
	vars.bgp_crit    = 22000
}
```

Example 3: IPv4 peer, specify router type and warn if prefix count is above 130
```
object Service "BGP-Customer-B" {
	import           = "template-default-import"
	host_name        = "router3.example.ca"
	check_command    = "bgp"

	vars.bgp_peerip  = "fd09:b422:3185::ABBD"
	vars.bgp_snmpcom = "c0mmun1ty"
	vars.bgp_snmpver = 2

	vars.bgp_type    = "cisco"
	vars.bgp_pfxhigh = true
	vars.bgp_warn    = 130
}
```


