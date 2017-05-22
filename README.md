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
1. [Check BGP](#check-bgp)
2. [Check EIGRP](#check-eigrp)
3. [Check Cisco WLAN](#check-cisco-wlan)


## Check BGP

##### Perl Modules

  Monitoring::Plugin, Net::IP, Net::SNMP, Socket


##### Vendor Support

 The following has been verified to be working based on recent equipment and recent code.
 - Arista
 - Brocade
 - Cisco
 - Juniper
 - Generic [BGP4-MIB RFC4273]

##### Installation

The following configuration can be placed in /etc/icinga2/include/plugins-contrib.d on CentOS 7 systems.
```
FILE: /etc/icinga2/include/plugins-contrib.d/bgp.conf

/******************************************************************************
 * Icinga 2                                                                   *
 *
 */

object CheckCommand "bgp" {
        command = [ PluginDir + "/check_bgp.pl" ]

        arguments = {
                "-H" = {
                        value = "$address$"
                        required = true
                        description = "hostname or ip address of router"
                }
                "-r" = {
                        value = "$bgp_state$"
                        required = false
                        description = "BGP State result code to match"
                }
                "-d" = {
                        value = "$bgp_debug$"
                        required = false
                }
                "-s" = {
                        value = "$bgp_snmpcom$"
                        required = true
                }
                "-P" = {
                        value = "$bgp_snmpver$"
                        required = true
                }
                "-b" = {
                        value = "$bgp_peerip$"
                        required = true
                }
                "-t" = {
                        value = "$bgp_type$"
                        required = false
                }
                "-A" = {
                        value = "$bgp_pfxhigh$"
                        required = false
                }
                "-B" = {
                        value = "$bgp_pfxlow$"
                        required = false
                }
        }

        # Variables available for configuration, and their default

        vars.bgp_router         = "$address$"

        vars.bgp_snmpcom        = "$bgp_snmpcom$"
        vars.bgp_snmpver        = "$bgp_snmpver$"
        vars.bgp_crit           = ",,1"
        vars.bgp_warn           = ",,2"

        # VARS: Entries which don't have a default
        #       These are configured in the ${host}.conf file as variables.

        # vars.bgp_debug        = true/false
        # vars.bgp_pfxhigh      = true/false # use warn/crit for levels
        # vars.bgp_pfxlow       = true/false # use warn/crit for levels
        # vars.bgp_peerip       = "IP.addr.v4|ip:addr:V6"
        # vars.bgp_state        = 6
        # vars.bgp_type         = specific vendor, cisco, juniper, etc...
}
```

##### Configuration
There are a few variables which can be used tweaked for the different environments.  Some variables are mandatory and others are optional, they are listed.



bgp_snmpver variable will accept both version 2 and 3 options and requires the bgp_snmpcom variable to be set as well. [VAR: mandatory]
```
 vars.bgp_snmpver = 2|3
```

bgp_snmpcom variable will take alphanumeric entries enclosed by quotes.  If the SNMP version if 2 then the entry is simply the community string of the device.  Version 3 requires a more elaborate configuration.  The appropriate 'security level' (ie. noAuthNoPriv, authNoPriv, authPriv) is picked dynamically based on the options passed.

Available algorithms for authPass are HMAC-MD5-96 (MD5) and HMAC-SHA-96 (SHA1).  The privacy option supports CBC-DES (DES), CBC-3DES-EDE (3DES), or CFB128-AES-128 (AES).  [VAR: mandatory]
```
 vars.bgp_snmpcom = "value" 
 vars.bgp_snmpcom = "user:authPass:authProto:privPass:privProto"
```

bgp_peerip variable supports both IPv4 and IPv6 address notation.  An error is returned if the address is invalid. [VAR: mandatory]
```
 vars.bgp_peerip = "value"
```

bgp_pfxlow is a boolean based variable which, if set, will compare the result of a prefix count of accepted routes from the BGP neighbor and alert if warn/crit are also set. [VAR: optional]
```
 vars.bgp_pfxlow = true|false
```

bgp_pfxhigh is a boolean based variable.  Like it's counterpart bgp_pfxlow, if set, will alert if the thresholds are met according to warn/crit. [VAR: optional]
```
 vars.bgp_pfxhigh = true|false
```

bgp_type can be defined if the user would like to speed up the time it takes to poll a device.  By specifying a specific vendor the auto-discovery process does not run every single time.  Current values are based on vendors names, including generic. [VAR: optional]
```
 vars.bgp_type = "value"
```

bgp_verbose can be set to receive a little more information when polling a device in an attempt to troubleshoot an issue. [VAR: optional]

```
 vars.bgp_verbose = true|false
```

bgp_debug can be enabled if verbose was not providing enough information or you would like to see and track down some other issue. [VAR: optional]
```
 vars.bgp_debug = true|false
```


##### Configuration Examples


###### Example 1: IPv4 peer, auto-detect router type.
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

###### Example 2: IPv4 peer, auto-detect router type and warn if prefix count is below 25000, crit if below 22000
```
object Service "BGP-Peer-A" {
	import           = "template-default-import"
	host_name        = "router2.example.ca"
	check_command    = "bgp"

	vars.bgp_peerip  = "10.33.44.55"
	vars.bgp_snmpcom = "c0mmun1ty"
	vars.bgp_snmpver = 2

	vars.bgp_pfxlow  = true
	vars.bgp_warn    = 25000
	vars.bgp_crit    = 22000
}
```

###### Example 3: IPv6 peer, specific router type and warn if prefix count is above 130
```
object Service "BGP-Customer-B" {
	import           = "template-default-import"
	host_name        = "router3.example.ca"
	check_command    = "bgp"

	vars.bgp_peerip  = "fd09:b422:3185::abbd"
	vars.bgp_snmpcom = "c0mmun1ty"
	vars.bgp_snmpver = 2

	vars.bgp_type    = "cisco"
	vars.bgp_pfxhigh = true
	vars.bgp_warn    = 130
}
```

###### Example 4: IPv6 peer, specific router type, crit if prefix count above 512000 and use SNMPv3.
```
object Service "BGP-Customer-B" {
	import           = "template-default-import"
	host_name        = "router4.example.ca"
	check_command    = "bgp"

	vars.bgp_peerip  = "fd34:a422:443a::aedd"
	vars.bgp_snmpcom = "BobTheBuilder:DaP4ssw0rd:MD5:PrivP4ss:AES"
	vars.bgp_snmpver = 3

	vars.bgp_type    = "juniper"
	vars.bgp_pfxhigh = true
	vars.bgp_crit    = 512000
}
```



## Check EIGRP

##### Perl Modules

  Monitoring::Plugin, Net::IP, Net::SNMP, Socket


##### Vendor Support

 The following has been verified to be working with Cisco devices.


##### Installation

The following configuration can be placed in /etc/icinga2/include/plugins-contrib.d on CentOS 7 systems.
```
FILE: /etc/icinga2/include/plugins-contrib.d/eigrp.conf

/******************************************************************************
 * Icinga 2                                                                   *
 *
 */

object CheckCommand "eigrp" {
        command = [ PluginDir + "/check_eigrp.pl" ]

        arguments = {
                "-H" = {
                        value = "$address$"
                        required = true
                        description = "hostname or ip address of router"
                }
                "-r" = {
                        value = "$eigrpres$"
                        required = false
                        description = "Specific number of matches"
                }
                "-d" = {
                        value = "$eigrp_debug$"
                        required = false
                }
                "-s" = {
                        value = "$eigrp_snmpcom$"
                        required = true
                }
                "-P" = {
                        value = "$eigrp_snmpver$"
                        required = true
                }
                "-A" = {
                        value = "$eigrp_nbrhigh$"
                        required = false
                }
                "-B" = {
                        value = "$eigrp_nbrlow$"
                        required = false
                }
        }

        # Variables available for configuration, and their default

        vars.eigrp_router       = "$address$"

        vars.eigrp_snmpcom        = "$eigrp_snmpcom$"
        vars.eigrp_snmpver        = "$eigrp_snmpver$"
        vars.eigrp_crit           = ",,1"
        vars.eigrp_warn           = ",,2"

        # VARS: Entries which don't have a default
        #       These are configured in the ${host}.conf file as variables.

        # vars.eigrp_debug        = true/false
        # vars.eigrp_nbrhigh      = true/false # use warn/crit for levels
        # vars.eigrp_nbrlow       = true/false # use warn/crit for levels
}
```

##### Configuration
There are a few variables which can be used tweaked for the different environments.  Some variables are mandatory and others are optional, they are listed.



eigrp_snmpver variable will accept both version 2 and 3 options and requires the eigrp_snmpcom variable to be set as well. [VAR: mandatory]
```
 vars.eigrp_snmpver = 2|3
```

eigrp_snmpcom variable will take alphanumeric entries enclosed by quotes.  If the SNMP version if 2 then the entry is simply the community string of the device.  Version 3 requires a more elaborate configuration.  The appropriate 'security level' (ie. noAuthNoPriv, authNoPriv, authPriv) is picked dynamically based on the options passed.

Available algorithms for authPass are HMAC-MD5-96 (MD5) and HMAC-SHA-96 (SHA1).  The privacy option supports CBC-DES (DES), CBC-3DES-EDE (3DES), or CFB128-AES-128 (AES).  [VAR: mandatory]
```
 vars.eigrp_snmpcom = "value" 
 vars.eigrp_snmpcom = "user:authPass:authProto:privPass:privProto"
```

eigrp_nbrlow is a boolean based variable which, if set, will compare the result of total neighbor count of EIGRP neighbors and alert if warn/crit are also set. [VAR: optional]
```
 vars.eigrp_nbrlow = true|false
```

eigrp_nbrhigh is a boolean based variable.  Like it's counterpart eigrp_nbrlow, if set, will alert if the thresholds are met according to warn/crit. [VAR: optional]
```
 vars.eigrp_nbrhigh = true|false
```


## Check Cisco WLAN

##### Perl Modules

  Monitoring::Plugin, Net::SNMP


##### Vendor Support

 The following has been verified to be working with Cisco WLC version 8.0 or higher.


##### Installation

The following configuration can be placed in /etc/icinga2/include/plugins-contrib.d on CentOS 7 systems.
```
FILE: /etc/icinga2/include/plugins-contrib.d/cisco_wlan.conf

/******************************************************************************
 * Icinga 2                                                                   *
 *
 */

object CheckCommand "cisco_wlan" {
        command = [ PluginDir + "/check_cisco_wlan.pl" ]

        arguments = {
                "-H" = {
                        value = "$address$"
                        required = true
                        description = "hostname or ip address of WLC"
                }
                "-r" = {
                        value = "$wlan_res$"
                        required = false
                        description = "Specific number of matches"
                }
                "-d" = {
                        value = "$wlan_debug$"
                        required = false
                }
                "-s" = {
                        value = "$wlan_snmpcom$"
                        required = true
                }
                "-P" = {
                        value = "$wlan_snmpver$"
                        required = true
                }
                "-A" = {
                        value = "$wlan_clienthigh$"
                        required = false
                }
                "-B" = {
                        value = "$wlan_clientlow$"
                        required = false
                }
        }

        # Variables available for configuration, and their default

        vars.wlan_snmpcom        = "$wlan_snmpcom$"
        vars.wlan_snmpver        = "$wlan_snmpver$"
        vars.wlan_crit           = ",,1"
        vars.wlan_warn           = ",,2"

        # VARS: Entries which don't have a default
        #       These are configured in the ${host}.conf file as variables.

	# vars.wlan_ssid	 = "GuestNetwork" # name of SSID
        # vars.wlan_debug        = true/false
        # vars.wlan_clienthigh   = true/false # use warn/crit for levels
        # vars.wlan_clientlow    = true/false # use warn/crit for levels
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
