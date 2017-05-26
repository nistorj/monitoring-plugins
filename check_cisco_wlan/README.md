# monitoring-plugins

Summary
-------
These monitoring plugins was designed to work with compatible NMS systems and utlize the Monitoring::Plugin modules in Perl.  Some examples are Icinga, Naemon, Nagios, and Shinken to name a few.  Each plugin has it's own documentation section below.


General Requirements
------------------
These monitoring tools are based on perl.  Some monitoring systems support embedded perl interpreter and some execute the perl each run.  Information about the perl modules required are listed per script.


Monitoring Scripts
------------------

#### Index
1. [Check Cisco WLAN](#check-cisco-wlan)


## Check Cisco WLAN

##### Perl Modules

Monitoring::Plugin, Net::SNMP, Socket, Socket6


##### Vendor Support

The following has been verified to be working with Cisco WLC version 8.0 or higher.


##### Installation

The following configuration can be placed in /etc/icinga2/include/plugins-contrib.d on CentOS 7 systems.
```
FILE: /etc/icinga2/include/plugins-contrib.d/cisco_wlan.conf

/******************************************************************************
 * Icinga 2                                                                   *
 *                                                                            *
 */

object CheckCommand "cisco_wlan" {
	command = [ PluginDir + "/check_cisco_wlan.pl" ]

	arguments = {
		"-H" = {
			value = "$address$"
			required = true
			description = "hostname or ip address of WLC"
		}
		"-P" = {
			value = "$wlan_snmpver$"
			required = false
			description = "SNMP version to use"
		}
		"-d" = {
			value = "$wlan_debug$"
			required = false
			description = "Do we enable debug?"
		}
		"-r" = {
			value = "$wlan_res$"
			required = false
			description = "Match specific number of clients"
		}
		"-s" = {
			value = "$wlan_snmpcom$"
			required = true
			description = "SNMP community to use, v3 include user,pass,auth, etc"
		}
		"-v" = {
			value = "$wlan_verbose$"
			required = false
			description = "Do we enable verbose?"
		}

		# ------------------------------------------
		# Plugin Specific Options
		"-4" = {
			value = "$wlan_v4$"
			required = false
			description = "Force IPv4 transport (udp)"
		}
		"-6" = {
			value = "$wlan_v6$"
			required = false
			description = "Force IPv6 transport (udp6)"
		}
		"-a" = {
			value = "$wlan_all$"
			required = false
			description = "Count all clients on WLC"
		}
		"-n" = {
			value = "$wlan_ssid$"
			required = false
			description = "Count clients for specific SSID"
		}
		"-A" = {
			value = "$wlan_clienthigh$"
			required = false
			description = "Enable alerting on client count too high"
		}
		"-B" = {
			value = "$wlan_clientlow$"
			required = false
			description = "Enable alerting on client count too low"
		}
	}

	# Variables available for configuration, and their default

	vars.wlan_snmpcom	= "$wlan_snmpcom$"
	# vars.wlan_snmpver	= "$wlan_snmpver$"
	vars.wlan_crit	   = ",,1"
	vars.wlan_warn	   = ",,2"

	# VARS: Entries which don't have a default
	#       These are configured in the ${host}.conf file as variables.

	# vars.wlan_ssid	 = "GuestNetwork" # name of SSID
	# vars.wlan_all		 = true/false # Total count on WLC
	# vars.wlan_debug	 = true/false
	# vars.wlan_clienthigh   = true/false # use warn/crit for levels
	# vars.wlan_clientlow    = true/false # use warn/crit for levels
	# vars.wlan_v4		 = true/false # Force IPv4 transport
	# vars.wlan_v6		 = true/false # Force IPv4 transport
}
```

##### Configuration
There are a few variables which can be used tweaked for the different environments.  Some variables are mandatory and others are optional, they are listed.


wlan_snmpver variable will accept both version 2 and 3 options and requires the eigrp_snmpcom variable to be set as well. [VAR: mandatory]
```
 vars.wlan_snmpver = 2|3
```

wlan_snmpcom variable will take alphanumeric entries enclosed by quotes.  If the SNMP version if 2 then the entry is simply the community string of the device.  Version 3 requires a more elaborate configuration.  The appropriate 'security level' (ie. noAuthNoPriv, authNoPriv, authPriv) is picked dynamically based on the options passed.

Available algorithms for authPass are HMAC-MD5-96 (MD5) and HMAC-SHA-96 (SHA1).  The privacy option supports CBC-DES (DES), CBC-3DES-EDE (3DES), or CFB128-AES-128 (AES).  [VAR: mandatory]
```
 vars.wlan_snmpcom = "value" 
 vars.wlan_snmpcom = "user:authPass:authProto:privPass:privProto"
```

wlan_clientlow is a boolean based variable which, if set, will compare the result of total client count of wireless clients and alert if warn/crit are also set. [VAR: optional]
```
 vars.wlan_clientlow = true|false
```

wlan_clienthigh is a boolean based variable.  Like it's counterpart wlan_clientlow, if set, will alert if the thresholds are met according to warn/crit. [VAR: optional]
```
 vars.wlan_clienthigh = true|false
```
