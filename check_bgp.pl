#!/usr/bin/perl
#
# Copyright (C) 2017 Jon Nistor
#
# --
# Author:	Jon Nistor (nistor@snickers.org)
# Purporse:	Monitoring Plugin to check for BGP sessions (v4/v6) and alert
#		if the prefix count is above or below a threshold.
# MIB:		Based on CISCO-BGP4-MIB, BGP4-V2-MIB-JUNIPER, BGP4V2-MIB, ARISTA-BGP4V2-MIB
# Vendors:	Cisco, Juniper, Arista, Brocade
#
# Version:	0.03
#
# History:
#  2017-05-08	0.03	Added support for Arista, Brocade
#  2017-05-04	0.02	Modified to support multiple vendors
#  2017-04-29	0.01	Initial
#
#
# --
# NOTE: Plugin Exit Codes (ref: https://docs.icinga.com/latest/en/pluginapi.html#returncode)
# 	RetCode	Svc-State	Host State
#	0	OK		UP
#	1	WARNING		UP or DOWN/UNREACHABLE
#	2	CRITICAL	DOWN/UNREACHABLE
#	3	UNKNOWN		DOWN/UNREACHABLE
#
# --
# Hash information of bgpPeer information
#	afinet		=> (1,2)	1: ipv4, 2: ipv6
#	errCode		=> Cease/subcode
#	errText		=> Textual representation
#	localAS		=> Our own AS number
#	remoteAS	=> neighbor AS number
#	type		=> iBGP/eBGP
#	state		=> Integer representation, 1..6
#	stateName	=> Textual representation, Idle, .. etc.., Established
#	remoteAddr	=> IP representation
#	remoteAddrOID	=> OID representation of IP address
#	  ... if available also ..
#	localAddr	=> IP representation
#	localAddrOID	=> OID representation of IP address
# --
# BASED ON SNMP OUTPUT FROM VARIOUS VENDORS, OPTIMIZATIONS COULD BE DONE.
# [maybe later?]
#

use Monitoring::Plugin;
use Monitoring::Plugin::Getopt;
use Monitoring::Plugin::Threshold;
use Net::IP;
use Net::SNMP qw(oid_lex_sort);
use Socket;
#
use strict;
use constant VERSION => '0.03';

$SIG{'ALRM'} = sub {
	plugin_exit( UNKNOWN, "Plugin took too long to complete (alarm)");
};


# -----------------------------------------------------------------------------
# PROG: Build initial object
my $np = Monitoring::Plugin->new(
	shortname	=> "",
	usage		=> "Usage: %s [-H|--host <router>] [-P|--snmpver <2|3>]" .
			   " [-s|--snmpcomm <comm>] [-d|--debug] [-v|--verbose]" .
			   " [-b|--bgpip <peer.ip>] [-t|--type <vendor>]" .
			   " [-r|--result <num>]" .
			   " [-A|--bgphigh] [-B|--bgplow]" .
			   " [-w|--warning <pfxCount>] [-c|--critical <pfxCount>]" .
			   "",
	version		=> VERSION,
	url		=> 'https://github.com/nistorj/monitoring-plugins',
	blurb		=> 'Check BGP neighbor status'
);

# -----------------------------------------------------------------------------
# PROG: Building arguments list, usage/help documentation
#
#	-b | --bgp	BGP IP.addr
#	-d | --debug	Enable debug output (not to be used in production)
#	-H | --host	Hostname of BGP router to poll
#	-r | --result	Integer value for BGP state returned (1..6)
#	-s | --snmpcomm	SNMP community of the router
#	-P | --snmpver	SNMP version to use in polling
#	-t | --type	Router Type: cisco, juniper
#	-v | --verbose	Provide a little more output
#	-A | --bgphigh	true:false alert on prefixes above.
#	-B | --bgplow	true:false alert on prefixes below.

$np->add_arg(
	spec	 => 'bgp|b=s',
	help	 => '-b, --bgp=IP.ADDR of BGP peeer (v4/v6)',
	default	 => undef,
	required => 1
);

$np->add_arg(
	spec	 => 'debug|d',
	help	 => '-d, --debug output',
	default	 => undef,
	required => 0
);

$np->add_arg(
	spec	 => 'host|H=s',
	help	 => '-H, --host=HOSTNAME of BGP router to poll',
	default	 => undef,
	required => 1
);

$np->add_arg(
	spec	 => 'result|r=s',
	help	 => '-r, --result=INTEGER  Integer value of BGP State',
	default	 => undef,
	required => 0
);

$np->add_arg(
	spec	 => 'snmpcomm|s=s',
	help	 => '-s, --snmpcomm=STRING Communtiy read string',
	default	 => undef,
	required => 1,
);

$np->add_arg(
	spec	 => 'snmpver|P=s',
	help	 => '-P, --snmpver=(2|3) SNMP polling version',
	default	 => 2,
	required => 0
);

$np->add_arg(
	spec	 => 'type|t=s',
	help	 => '-t, --type=<vendor> Types include cisco, juniper',
	default	 => undef,
	required => 0
);

$np->add_arg(
	spec	 => 'verbose|v',
	help	 => '-v, --verbose display more information',
	default	 => undef,
	required => 0
);

$np->add_arg(
	spec	 => 'bgphigh|A',
	help	 => '-A, --bgphigh alert if prefix count is above value',
	default	 => undef,
	required => 0
);

$np->add_arg(
	spec	 => 'bgplow|B',
	help	 => '-B, --bgplow alert if prefix count drops below value',
	default	 => undef,
	required => 0
);

$np->add_arg(
	spec	 => 'warning|w=s',
	help	 => 'warning threshold',
	required => 0
);

$np->add_arg(
	spec	 => 'critical|c=s',
	help	 => 'critical threshold',
	required => 0
);

my $threshold_state = Monitoring::Plugin::Threshold->set_thresholds(
	warning	 => $np->opts->{'warning'},
	critical => $np->opts->{'critical'}
);


# Parse @ARGV and process standard arguments (e.g. usage, help, version)
$np->getopts;


if( defined( $np->opts->{'debug'} ) &&
	     $np->opts->{'debug'} == 1 ) # Enable up verbose as well?
{
	$np->opts->{'verbose'} = 1;

	#  DBG: Print out args passed
	print " OPT: Passing arguments.. \n";
	print " OPT:      bgp: " . $np->opts->{'bgp'} . "\n"; 
	print " OPT:     host: " . $np->opts->{'host'} . "\n";
	print " OPT:  snmpver: " . $np->opts->{'snmpver'} . "\n";
	print " OPT:   bgplow: " . $np->opts->{'bgplow'} . "\n";
	print " OPT:  bgphigh: " . $np->opts->{'bgphigh'} . "\n";
	print " OPT:     warn: " . $np->opts->{'warning'} . "\n";
	print " OPT:     crit: " . $np->opts->{'critical'} . "\n";
}


# ------------------------------------------------------------------------------
#
my( $bgpOBJ, $bgpOID, %bgpPeer );
if( $np->opts->{'bgp'} )
{
	$bgpOBJ		= new Net::IP( $np->opts->{'bgp'} );
	$bgpOID		= _convert_IP_to_OID($np->opts->{'bgp'});
	$bgpPeer{'IP'}	= $bgpOBJ->short();
} else {
	$np->plugin_exit( UNKNOWN, "-b|--bgp <neigh.addr> has not been specified" );
}

sub _convert_IP_to_OID
{
	my $s_arg	= shift;	# IPaddr v4|v6
	my $s_IP	= new Net::IP( $s_arg ) ||
				$np->plugin_exit( UNKNOWN, "Invalid IP addr: $s_arg" );

	if( $s_IP->version() == 4 )
	{
		return $s_arg;
	} elsif ( $s_IP->version() == 6 )
	{
		my $IPlong	=  $s_IP->ip();
		   $IPlong	=~ s/://g;

		# PROG: Split the entry every 2 chars
		my @IParr	= unpack("(a2)*", $IPlong);
		my $IPoid;
		foreach my $v (@IParr)
		{
			# LOOP: Build OID
			$IPoid .= hex($v) . ".";
		}

		$IPoid	=~ s/.$//g;
		return $IPoid;
	} else {
		$np->plugin_exit( UNKNOWN, "Invalid IP version for: $s_arg");
	}
}

# -----------------------------------------------------------------------------
# SNMP: mib:oid information

my $bgpAdminStatus = (
	1 => 'Stop',
	2 => 'Start'
);


my %bgpOIDtable	= (
	# -----------------------------------------------------------------------------
	# GENERIC
	# NOTE: Using the BGP4-MIB (https://tools.ietf.org/html/rfc4273)
	#	-
	#	This MIB does NOT support Prefix counts.
	'sysObjectID'			=> '1.3.6.1.2.1.1.2.0',
	'bgpLocalAs'			=> '1.3.6.1.2.1.15.2.0',

	'generic'			=> '1.3.6.1.2.1.15.3.1.2', # used for auto-detect
	'bgpPeerState'			=> '1.3.6.1.2.1.15.3.1.2',
	'bgpPeerAdminStatus'		=> '1.3.6.1.2.1.15.3.1.3',
	'bgpPeerLocalAddr'		=> '1.3.6.1.2.1.15.3.1.5',
	'bgpPeerRemoteAddr'		=> '1.3.6.1.2.1.15.3.1.7',
	'bgpPeerRemoteAs'		=> '1.3.6.1.2.1.15.3.1.9',
	'bgpPeerLastError'		=> '1.3.6.1.2.1.15.3.1.14',


	# -----------------------------------------------------------------------------
	# ARISTA
	# NOTE: Based on ARISTA-BGP4V2-MIB
	'arista'			   => '1.3.6.1.4.1.30065.4.1.1.2.1.13',
	'aristaBgp4V2PeerTable'		   => '1.3.6.1.4.1.30065.4.1.1.2',

	'aristaBgp4V2PeerLocalAddrType'	   => '1.3.6.1.4.1.30065.4.1.1.2.1.2',
	'aristaBgp4V2PeerLocalAddr'	   => '1.3.6.1.4.1.30065.4.1.1.2.1.3',
	'aristaBgp4V2PeerRemoteAddrType'   => '1.3.6.1.4.1.30065.4.1.1.2.1.4',
	'aristaBgp4V2PeerRemoteAddr'	   => '1.3.6.1.4.1.30065.4.1.1.2.1.5',
	'aristaBgp4V2PeerLocalAs'	   => '1.3.6.1.4.1.30065.4.1.1.2.1.7',
	'aristaBgp4V2PeerRemoteAs'	   => '1.3.6.1.4.1.30065.4.1.1.2.1.10',
	'aristaBgp4V2PeerAdminStatus'	   => '1.3.6.1.4.1.30065.4.1.1.2.1.12',
	'aristaBgp4V2PeerState'		   => '1.3.6.1.4.1.30065.4.1.1.2.1.13',
	'aristaBgp4V2PeerDescription'	   => '1.3.6.1.4.1.30065.4.1.1.2.1.14',
	'aristaBgp4V2PeerLastErrorCodeReceived'    => '1.3.6.1.4.1.30065.4.1.1.3.1.1',
	'aristaBgp4V2PeerLastErrorSubCodeReceived' => '1.3.6.1.4.1.30065.4.1.1.3.1.2',
	'aristaBgp4V2PeerLastErrorReceivedText'    => '1.3.6.1.4.1.30065.4.1.1.3.1.4',
	#
	'aristaBgp4V2PrefixInPrefixes'	=> '1.3.6.1.4.1.30065.4.1.1.8.1.3',


	# -----------------------------------------------------------------------------
	# CISCO
	#
	# NOTE: The number 4 and 16 at the end of the ipv4/ipv6 represents
	#       The number of oid slots there are after the end of the oid.
	#       ie: ...3.1.4.206.108.35.254 <-- 4 slots after the 3.1.4...
	#	Based on CISCO-BGP4-MIB

	'cbgpPeer2Entry'		 => '1.3.6.1.4.1.9.9.187.1.2.5.1',	# Table pull

	'cisco'				 => '1.3.6.1.4.1.9.9.187.1.2.5.1.3', # used for auto-detect
	'cbgpPeer2State'		 => '1.3.6.1.4.1.9.9.187.1.2.5.1.3',
	'cbgpPeer2AdminStatus'		 => '1.3.6.1.4.1.9.9.187.1.2.5.1.4', # 1 = stop, 2 = start
	'cbgpPeer2LocalAs'		 => '1.3.6.1.4.1.9.9.187.1.2.5.1.8', # used with bgp local-as
	'cbgpPeer2RemoteAs'		 => '1.3.6.1.4.1.9.9.187.1.2.5.1.11',
	'cbgpPeer2LastError'		 => '1.3.6.1.4.1.9.9.187.1.2.5.1.17',
	'cbgpPeer2LastErrorTxt'		 => '1.3.6.1.4.1.9.9.187.1.2.5.1.28',
	'cbgpPeer2AcceptedPrefixes'	 => '1.3.6.1.4.1.9.9.187.1.2.8.1.1', # endOID .1.1 (af|unicast)

	# -----------------------------------------------------------------------------
	# FORCE-10
	# NOTE: Based on FORCE10-BGP4-V2-MIB
	'f10BgpM2PeerTable'		=> '1.3.6.1.4.1.6027.20.1.2.1.1',
	#
	'f10BgpM2PeerIdentifier'	=> '1.3.6.1.4.1.6027.20.1.2.1.1.1.2',
	'f10BgpM2PeerStatus'		=> '1.3.6.1.4.1.6027.20.1.2.1.1.1.4',
	'f10BgpM2PeerLocalAddr'		=> '1.3.6.1.4.1.6027.20.1.2.1.1.1.8',
	'f10BgpM2PeerRemoteAddrType'	=> '1.3.6.1.4.1.6027.20.1.2.1.1.1.11',
	'f10BgpM2PeerRemoteAddr'	=> '1.3.6.1.4.1.6027.20.1.2.1.1.1.12',
	'f10BgpM2PeerRemoteAs'		=> '1.3.6.1.4.1.6027.20.1.2.1.1.1.14',
	'f10BgpM2PeerIndex'		=> '1.3.6.1.4.1.6027.20.1.2.1.1.1.15',
	#
	'f10BgpM2PrefixCountersSafi'	=> '1.3.6.1.4.1.6027.20.1.2.6.2.1.2',


	# -----------------------------------------------------------------------------
	# BROCADE
	# NOTE: Based on BGP4V2-MIB
	#  URL: http://www.brocade.com/content/html/en/mib-reference-guide/
	#	ipmib-feb2016-reference/GUID-C9294495-3C42-4267-A36A-561D7A536B6B.html
	'brocade'			=> '1.3.6.1.4.1.1991.3.5.1.1.2.1.13',
	#
	'bgp4V2PeerEntry'		=> '1.3.6.1.4.1.1991.3.5.1.1.2.1',
	'bgp4V2PeerLocalAddrType'	=> '1.3.6.1.4.1.1991.3.5.1.1.2.1.2', # not accessible
	'bgp4V2PeerLocalAddr'		=> '1.3.6.1.4.1.1991.3.5.1.1.2.1.3', # not accessible
	'bgp4V2PeerRemoteAddrType'	=> '1.3.6.1.4.1.1991.3.5.1.1.2.1.4', # not accessible
	'bgp4V2PeerRemoteAddr'		=> '1.3.6.1.4.1.1991.3.5.1.1.2.1.5', # not accessible
	'bgp4V2PeerLocalAs'		=> '1.3.6.1.4.1.1991.3.5.1.1.2.1.7',
	'bgp4V2PeerRemoteAs'		=> '1.3.6.1.4.1.1991.3.5.1.1.2.1.10',
	'bgp4V2PeerAdminStatus'		=> '1.3.6.1.4.1.1991.3.5.1.1.2.1.12',
	'bgp4V2PeerState'		=> '1.3.6.1.4.1.1991.3.5.1.1.2.1.13',
	'bgp4V2PeerLastErrorCodeReceived'    => '1.3.6.1.4.1.1991.3.5.1.1.3.1.1',
	'bgp4V2PeerLastErrorSubCodeReceived' => '1.3.6.1.4.1.1991.3.5.1.1.3.1.2',
	#
	'snBgp4NeighborSummaryIp'	     => '1.3.6.1.4.1.1991.1.2.11.17.1.1.2',
	'snBgp4NeighborSummaryRouteReceived' => '1.3.6.1.4.1.1991.1.2.11.17.1.1.5',


	# -----------------------------------------------------------------------------
	# JUNIPER
	#  Using JunOS 17.1 MIBs
	#  (http://www.juniper.net/documentation/en_US/release-independent/junos/mibs/mibs.html)

	'juniper'			 => '1.3.6.1.4.1.2636.5.1.1.2.1.1.1.2',	# used for auto-detect
	'jnxBgpM2PeerState'		 => '1.3.6.1.4.1.2636.5.1.1.2.1.1.1.2',
	'jnxBgpM2PeerStatus'		 => '1.3.6.1.4.1.2636.5.1.1.2.1.1.1.3', # Admin Status
	'jnxBgpM2PeerLocalAs'		 => '1.3.6.1.4.1.2636.5.1.1.2.1.1.1.9',
	'jnxBgpM2PeerRemoteAs'		 => '1.3.6.1.4.1.2636.5.1.1.2.1.1.1.13',
	'jnxBgpM2PeerIndex'		 => '1.3.6.1.4.1.2636.5.1.1.2.1.1.1.14',
	'jnxBgpM2PeerLastErrorReceived'	 => '1.3.6.1.4.1.2636.5.1.1.2.2.1.1.1',
	'jnxBgpM2PeerLastErrorReceivedText' => '1.3.6.1.4.1.2636.5.1.1.2.2.1.1.5',
	'jnxBgpM2PrefixInPrefixesAccepted'  => '1.3.6.1.4.1.2636.5.1.1.2.6.2.1.8',
);

my %bgpAfi	= (
	  1 => 'ipv4',
	  2 => 'ipv6'
);

my %bgpSafi	= (
	# address family identifier (AFI)
	# https://www.iana.org/assignments/address-family-numbers/address-family-numbers.txt
	# -
	# subsequent address family identifier (SAFI)
	# https://www.iana.org/assignments/safi-namespace/safi-namespace.txt
	  1 => 'unicast',
	  2 => 'multicast',
	  3 => 'unicastAndMulticast',
	  4 => 'mpls',
	 65 => 'vpls',
	 66 => 'mdt',
	 67 => 'ipv4over6',
	 68 => 'ipv6over4',
	 70 => 'evpn',
	128 => 'vpn',
	129 => 'vpn multicast',
);

my %bgpState    = (
	1 => 'Idle',
	2 => 'Connect',
	3 => 'Active',
	4 => 'OpenSent',
	5 => 'OpenConfirm',
	6 => 'Established'
);

my %bgpSubcodes	= (
	# https://www.iana.org/assignments/bgp-parameters/bgp-parameters.txt
	'01 00' => 'Message Header Error',
	'01 01' => 'Message Header Error - Connection Not Synchronized',
	'01 02' => 'Message Header Error - Bad Message Length',
	'01 03' => 'Message Header Error - Bad Message Type',
	'02 00' => 'OPEN Message Error',
	'02 01' => 'OPEN Message Error - Unsupported Version Number',
	'02 02' => 'OPEN Message Error - Bad Peer AS',
	'02 03' => 'OPEN Message Error - Bad BGP Identifier',
	'02 04' => 'OPEN Message Error - Unsupported Optional Parameter',
	'02 05' => 'OPEN Message Error', #deprecated
	'02 06' => 'OPEN Message Error - Unacceptable Hold Time',
	'03 00' => 'UPDATE Message Error',
	'03 01' => 'UPDATE Message Error - Malformed Attribute List',
	'03 02' => 'UPDATE Message Error - Unrecognized Well-known Attribute',
	'03 03' => 'UPDATE Message Error - Missing Well-known Attribute',
	'03 04' => 'UPDATE Message Error - Attribute Flags Error',
	'03 05' => 'UPDATE Message Error - Attribute Length Erro',
	'03 06' => 'UPDATE Message Error - Invalid ORIGIN Attribute',
	'03 07' => 'UPDATE Message Error', #deprecated
	'03 08' => 'UPDATE Message Error - Invalid NEXT_HOP Attribute',
	'03 09' => 'UPDATE Message Error - Optional Attribute Error',
	'03 0A' => 'UPDATE Message Error - Invalid Network Field',
	'03 0B' => 'UPDATE Message Error - Malformed AS_PATH',
	'04 00' => 'Hold Timer Expired',
	'05 00' => 'Finite State Machine Error',
	'06 00' => 'Cease',
	'06 01' => 'Cease - Maximum Number of Prefixes Reached',
	'06 02' => 'Cease - Administrative Shutdown',
	'06 03' => 'Cease - Peer De-configured',
	'06 04' => 'Cease - Administrative Reset',
	'06 05' => 'Cease - Connection Rejected',
	'06 06' => 'Cease - Other Configuration Change',
	'06 07' => 'Cease - Connection Collision Resolution',
	'06 08' => 'Cease - Out of Resources'
);


# -----------------------------------------------------------------------------
# PROG: Construct SNMP session information.

my @snmpopts;

if( $np->opts->{'snmpver'} == 2 || $np->opts->{'snmpver'} eq "2c" )
{
	push(@snmpopts, 'community', $np->opts->{'snmpcomm'} );
}
elsif( $np->opts->{'snmpver'} == 3 )
{
	my ($v3_user,$v3_pass,$v3_prot,$v3_priv_pass,$v3_priv_prot)
		= split(":", $np->opts->{'snmpcomm'});

	if( defined($v3_user) )
	{
		push(@snmpopts, 'username', $v3_user);
	}

	if( defined($v3_pass) )
	{
		push(@snmpopts, ($v3_pass =~ /^0x/) ?
				'authkey' : 'authpassword', $v3_pass);
	}

	if( defined($v3_prot) )
	{
		push(@snmpopts, 'authprotocol', $v3_prot);
	}

	if( defined($v3_priv_pass) )
	{
		push(@snmpopts, ($v3_priv_pass =~ /^0x/) ?
				'privkey' : 'privpassword', $v3_priv_pass);
	}

	if( defined($v3_priv_prot) )
	{
		push(@snmpopts, 'privprotocol', $v3_priv_prot);
	}

	if( $np->opts->{'debug'} )
	{
		print "SNMP: v3 user $v3_user\n";
		print "SNMP: v3 authpass $v3_pass, authprot $v3_prot\n";
		print "SNMP: v3 privpass $v3_priv_pass, privprot $v3_priv_prot\n";
	}
}
elsif ( $np->opts->{'snmpcomm'} )
{
	# SNMP: Force v2 if nothing else.
	$np->opts->{'snmpver'}	= 2;
	push( @snmpopts, 'community', $np->opts->{'snmpcomm'} );
} else {
	$np->plugin_exit( UNKNOWN, "No proper SNMP ver/comm combo" );
}


my ($session, $error)	= Net::SNMP->session(
	-nonblocking	=> 0,
	-timeout	=> 15,
	-retries	=> 1,
	-hostname	=> $np->opts->{'host'},
	-version	=> $np->opts->{'snmpver'},
	-debug		=> 0x00,
	@snmpopts
);

if( $np->opts->{'debug'} )
{
	my %snmpVerMap = (
		0 => "v1",
		1 => "v2c",
		3 => "v3"
	   );
	#print "SNMP: dispatching with " . $snmpVerMap{$session->version()} . "\n";
}

if( not defined($session) )
{
	$np->plugin_exit( CRITICAL, "SNMP session check failed: " . $error );
	exit(1);
}



# -----------------------------------------------------------------------------
# PROG: Start process of polling a BGP neighbor

# CHECK: Validate router type is right
my $result;
my $s_vendor;
my $s_baseoid;
my @snmpoids;

if( defined($np->opts->{'type'}) )
{
	#  RTR: Specify the router type so it doesn't do auto-discovery.
	#
	if( $np->opts->{'verbose'} )
	{
	    print " BGP: Polling for router type " . $np->opts->{'type'} . "\n";
	}
	$s_vendor	= lc($np->opts->{'type'});
	$result		= $session->get_table( -baseoid => $bgpOIDtable{$s_vendor} );

	if( not defined($result) )
	{
		$np->plugin_exit( CRITICAL, "Router type not defined correctly, or other error." );
	}

	my $ip		= $np->opts->{'bgp'};
	my $e_subname	= "_bgp_$s_vendor";
	eval $e_subname;
} else {
	# ----
	#
	# RTR: Try cisco -> juniper -> <vendor> -> generic --> exit;
	#
	#  --> Cisco
	$result  = $session->get_table( -baseoid => $bgpOIDtable{'cisco'} );
	if( defined($result) )
	{
		$s_vendor	= "cisco";
		print " BGP: Vendor detected -> $s_vendor\n" if( $np->opts->{'verbose'} );
		_bgp_cisco($np->opts->{'bgp'});
	}

	#  --> Juniper
	if( not defined($s_vendor) )
	{
	    $result	= $session->get_table( -baseoid => $bgpOIDtable{'juniper'} );

	    if( defined($result) )
	    {
		$s_vendor	= "juniper";
		print " BGP: Vendor detected -> $s_vendor\n" if( $np->opts->{'verbose'} );
		_bgp_juniper($np->opts->{'bgp'});
   	    }
	}

	#  --> Brocade
	if( not defined($s_vendor) )
	{
	    $result	= $session->get_table( -baseoid => $bgpOIDtable{'brocade'} );

	    if( defined($result) )
	    {
		$s_vendor	= "brocade";
		print " BGP: Vendor detected -> $s_vendor\n" if( $np->opts->{'verbose'} );
		_bgp_brocade($np->opts->{'bgp'});
   	    }
	}

	#  --> Arista
	if( not defined($s_vendor) )
	{
	    $result	= $session->get_table( -baseoid => $bgpOIDtable{'arista'} );

	    if( defined($result) )
	    {
		$s_vendor	= "arista";
		print " BGP: Vendor detected -> $s_vendor\n" if( $np->opts->{'verbose'} );
		_bgp_arista($np->opts->{'bgp'});
   	    }
	}

	# --> Generic BGP4-MIB
	if( not defined($s_vendor) )
	{
	    $result	= $session->get_table( -baseoid => $bgpOIDtable{'generic'} );

	    if( defined($result) )
	    {
		$s_vendor	= "generic";
		print " BGP: Vendor detected -> $s_vendor\n" if( $np->opts->{'verbose'} );
		_bgp_generic($np->opts->{'bgp'});
	    }
	}
}

# --
if( not defined( $s_vendor ) )
{
	$np->plugin_exit( CRITICAL, "Unable to determine vendor, can't continue.");
}



# ------------------------------------------------------------------------------
#
sub _raw_debug
{
	my $data = shift;
	use Data::Dumper;
	$Data::Dumper::Indent = 3;
	print Dumper($data);
}


# ------------------------------------------------------------------------------
#
sub _ip_version
{
	# NOTE: Validate IP address being passed.
	my $l_ip	= shift;
	my $n_ip	= new Net::IP($l_ip);
	return $n_ip->version() || undef;
}

# ------------------------------------------------------------------------------
#
sub _bgp_generic
{
	if( $np->opts->{'debug'} )
	{
		print " SUB: Function _bgp_generic processing ...\n";
	}
	#
	# NOTE: This function only supports IPv4.  BGP4-MIB does not support
	#	multiple AFinets.

	my $peerIP	= shift || $np->opts->{'bgp'};
	my $peerAFinet	= _ip_version($peerIP) ||
			  $np->plugin_exit( CRITICAL, "Not a valid IP address" );

	if( $peerAFinet == 6 )
	{
		$np->plugin_exit( CRITICAL, "This router's MIB doesn't support IPv6" );
	}

	if( defined($np->opts->{'critical'}) || defined($np->opts->{'warning'}) )
	{
		$np->plugin_exit( UNKNOWN, "This router doesn't expose prefix count. " .
				"Unable to use -w and -c flags" );
	}

	my $p_State	= $bgpOIDtable{'bgpPeerState'} . "." . $bgpOID;
	my $p_Status	= $bgpOIDtable{'bgpPeerAdminStatus'} . "." . $bgpOID;
	my $p_LocalAS	= $bgpOIDtable{'bgpLocalAs'};
	my $p_RemoteAS	= $bgpOIDtable{'bgpPeerRemoteAs'} . "." . $bgpOID;
	my $p_errCode	= $bgpOIDtable{'bgpPeerLastError'} . "." . $bgpOID;

	push( @snmpoids, $p_State, $p_Status, $p_LocalAS, $p_RemoteAS);
	push( @snmpoids, $p_errCode );

	if( $np->opts->{'verbose'} )
	{
		print "POLL: Attempting to poll state, admStatus, ASN, error Codes, etc..\n";
	}

	if( $np->opts->{'debug'} )
	{
		print "POLL: \@snmpoids -> @snmpoids\n";
	}

	my $s_result = $session->get_request( -varbindlist => \@snmpoids );

	if( not defined( $s_result ) )
	{
		$session->close;
		$np->plugin_exit( CRITICAL, "BGP neighbor not configured ?" );
	} else {
		$session->close;
	}

	if( $s_result->{$p_State} eq "noSuchInstance" || not defined($s_result->{$p_State}) )
	{
		$np->plugin_exit( UNKNOWN, "BGP error: Does peer exist on this router?" );
	}

	$bgpPeer{'state'}	= $s_result->{$p_State};
	$bgpPeer{'stateName'}	= $bgpState{$s_result->{$p_State}};
	$bgpPeer{'admStatus'}	= $s_result->{$p_Status};
	$bgpPeer{'localAS'}	= $s_result->{$p_LocalAS};
	$bgpPeer{'remoteAS'}	= $s_result->{$p_RemoteAS};
	$bgpPeer{'errCode'}	= $s_result->{$p_errCode};

	if( hex($bgpPeer{'errCode'}) != 0 )
	{
		my $hashCode	= substr($bgpPeer{'errCode'}, 2, 2) . " " .
				  substr($bgpPeer{'errCode'}, 4, 2);
		$bgpPeer{'errText'}	= $bgpSubcodes{$hashCode};
	}

	if( $bgpPeer{'localAS'} == $bgpPeer{'remoteAS'} )
	{
		$bgpPeer{'type'} = "iBGP";
	} else {
		$bgpPeer{'type'} = "eBGP";
	}
}

# ------------------------------------------------------------------------------
sub _bgp_arista
{
	if( $np->opts->{'debug'} )
	{
		print " SUB: Function _bgp_arista processing ...\n";
	}
	#
	# NOTE: This function takes into account Arista Routers (ARISTA-BGP4V2-MIB)

	my $peerIP	= shift || $np->opts->{'bgp'};
	my $peerAFinet	= _ip_version($peerIP) ||
			  $np->plugin_exit( CRITICAL, "Not a valid IP address" );

	# PROG: First we need to pull the table to start indexing entries
	my $result	= $session->get_table( -baseoid => $bgpOIDtable{'aristaBgp4V2PeerState'} );
	if( not defined($result) )
	{
		$session->close;
		np->plugin_exit( UNKNOWN, "Router doesn't support ARISTA-BGP4V2-MIB::aristaBgp4V2PeerState" );
	}

	# -- Find specific peer information
	my $peerMatch = 0;
	my $peerAFinetOID; # set below
	PEEROID: foreach my $l_snmpOID ( oid_lex_sort( keys( %{$result}) ) )
	{
		next if( $l_snmpOID !~ /$bgpOID$/ ); # Find specific peer or skip entry.
		$peerMatch = 1;

		my $baseLength	= length( $bgpOIDtable{'aristaBgp4V2PeerState'} ) + 1;
		my $l_vars	= substr( $l_snmpOID, $baseLength );

		my $l_instance	= substr( $l_vars, 0, 1);
		my $l_afinet	= substr( $l_vars, 2, 1);

		$bgpPeer{'instance'}	= $l_instance;  # Routing Instance
		$bgpPeer{'afinet'}	= $l_afinet;	# 1: ipv4, 2: ipv6 (as per INET-ADDRESS-MIB)
		$bgpPeer{'remoteAddrOID'} = _convert_IP_to_OID($np->opts->{'bgp'});

		if( $l_afinet == 1 )
		{
		    # -- IPv4 found
		    $peerAFinetOID = "1.4"; # ipv4, 4 entries following
		    $bgpPeer{'afinetOID'} = "1.4";

		    if( $l_vars =~ /^$l_instance.$peerAFinetOID/ )
		    {
			my @l_localaddrArr	= split( /\./, $l_vars, -1 );
			# LOOP: count is 3rd position to the 6th (4 octets)
			foreach ( 3 .. 6 )
			{
			    if( $_ == 6 )
			    {
				$bgpPeer{'localAddrOID'} .= $l_localaddrArr[$_];
			    } else {
				$bgpPeer{'localAddrOID'} .= $l_localaddrArr[$_] . ".";
			    }
			} #end:foreach
		    }
		}
		elsif ( $l_afinet == 2 )
		{
		    # == IPv6 found
		    $peerAFinetOID = "2.16"; # ipv6, 16 entries following
		    $bgpPeer{'afinetOID'} = "2.16";

		    if( $l_vars =~ /^$l_instance.$peerAFinetOID/ )
		    {
			my @l_localaddrArr	= split( /\./, $l_vars, -1 );
			$bgpPeer{'localAddr'}	= $np->opts->{'bgp'};  # -nistor: FIXME

			# LOOP: count is 2nd position to the 17th
			foreach ( 3 .. 18 )
			{
			    if( $_ == 18 )
			    {
				$bgpPeer{'localAddrOID'} .= $l_localaddrArr[$_];
			    } else {
				$bgpPeer{'localAddrOID'} .= $l_localaddrArr[$_] . ".";
			    }
			} # end:foreach
		    } # end: if l_vars
		} else {
			$np->plugin_exit( CRITICAL, "AFInet is not ipv4 or ipv6" );
		} # end: afinet
	}

	# SNMP: Prep variables to be polled.
	my $s_subOID	= $bgpPeer{'instance'} . "." . $bgpPeer{'afinetOID'} . "." .
			  $bgpPeer{'remoteAddrOID'};

	my $p_bgpASN	= $bgpOIDtable{'bgpLocalAs'};
        my $p_State	= $bgpOIDtable{'aristaBgp4V2PeerState'}       . "." . $s_subOID;
	my $p_Status	= $bgpOIDtable{'aristaBgp4V2PeerAdminStatus'} . "." . $s_subOID;
	my $p_LocalAS	= $bgpOIDtable{'aristaBgp4V2PeerLocalAs'}     . "." . $s_subOID;
	my $p_RemoteAS	= $bgpOIDtable{'aristaBgp4V2PeerRemoteAs'}    . "." . $s_subOID;
	my $p_errCode	 = $bgpOIDtable{'aristaBgp4V2PeerLastErrorCodeReceived'}
			   . "." . $s_subOID;
	my $p_errSubCode = $bgpOIDtable{'aristaBgp4V2PeerLastErrorSubCodeReceived'}
			   . "." . $s_subOID;

	my $p_Prefixes;	# Compute after we get the table entry for SAFI.
	my $p_SAFI;	# Compute after we get the table entry for SAFI.

	# SNMP: Cross reference prefixes table for peer type.
	my $p_PfxTbl	= $bgpOIDtable{'aristaBgp4V2PrefixInPrefixes'} . "." . $s_subOID;
	my $result_pfx	= $session->get_table( -baseoid => $p_PfxTbl );
	if( keys( %{$result_pfx} ) == 1 ) # Count entries.
	{
		#  OID: Parse and set in hash.
		my $l_key	= each %{$result_pfx};
		my $l_afinet	= (split(/\./, substr( $l_key, -3 )))[0];
		my $l_safi	= substr( $l_key, -1 );

		$p_Prefixes	= $l_key;
		$bgpPeer{'safi'} = $l_safi;

		if( $np->opts->{'verbose'} )
		{
			print " BGP: session is " . $bgpAfi{$l_afinet} . "-" . $bgpSafi{$l_safi} . "\n";
		}
	} else {
		$np->plugin_exit( WARNING, "Multiple Prefix SAFI detected, bailing." );
	}

	my @snmpoids;
	push( @snmpoids, $p_State, $p_Status, $p_LocalAS, $p_RemoteAS);
	push( @snmpoids, $p_errCode, $p_errSubCode, $p_Prefixes );

	if( $np->opts->{'verbose'} )
	{
		print "POLL: Attempting to poll state, admStatus, ASN, error Codes, etc..\n";
	}
	if( $np->opts->{'debug'} )
	{
		print "POLL: \@snmpoids -> " . join("\n  ", @snmpoids) . "\n";
	}

	my $s_result = $session->get_request( -varbindlist => \@snmpoids );

	if( not defined( $s_result ) )
	{
		$session->close;
		$np->plugin_exit( UNKNOWN, "BGP neighbor not configured ?" );
	} else {
		$session->close;
	}

	if( $s_result->{$p_State} eq "noSuchInstance" || not defined($s_result->{$p_State}) )
	{
		$np->plugin_exit( UNKNOWN, "BGP error: Does peer exist on this router?" );
	}

	$bgpPeer{'state'}	= $s_result->{$p_State};
	$bgpPeer{'stateName'}	= $bgpState{$s_result->{$p_State}};
	$bgpPeer{'admStatus'}	= $s_result->{$p_Status};
	$bgpPeer{'localAS'}	= $s_result->{$p_LocalAS} ?
				  $s_result->{$p_LocalAS} : $s_result->{$p_bgpASN};
	$bgpPeer{'remoteAS'}	= $s_result->{$p_RemoteAS};
	$bgpPeer{'errCode'}	= $s_result->{$p_errCode};
	$bgpPeer{'errSubCode'}	= $s_result->{$p_errSubCode};
	$bgpPeer{'prefixes'}	= $s_result->{$p_Prefixes};

	my $t_err		= sprintf("%02X %02X", $bgpPeer{'errCode'}, $bgpPeer{'errSubCode'}) ;
	$bgpPeer{'errText'}	= $bgpSubcodes{$t_err};

	if( $bgpPeer{'localAS'} == $bgpPeer{'remoteAS'} )
	{
		$bgpPeer{'type'} = "iBGP";
	} else {
		$bgpPeer{'type'} = "eBGP";
	}
}


# ------------------------------------------------------------------------------
sub _bgp_brocade
{
	if( $np->opts->{'debug'} )
	{
		print " SUB: Function _bgp_brocade processing ...\n";
	}
	#
	# NOTE: This function takes into account Brocade/Foundry routers using BGP4V2-MIB

	my $peerIP	= shift || $np->opts->{'bgp'};
	my $peerAFinet	= _ip_version($peerIP) ||
			  $np->plugin_exit( CRITICAL, "Not a valid IP address" );

	# PROG: If we are trying to warn on bgplow or high and IPv6, bail, not supported.
	if( ( defined($np->opts->{'bgplow'}) || defined($np->opts->{'bgphigh'}) ) &&
	    ( $peerAFinet == 6 ) )
	{
		$np->plugin_exit( UNKNOWN, "Device doesn't support v6 prefix count" );
	} else {

		# SNMP: Cross reference old NeighbourSummary table to get Index.
		my $p_idxTbl	= $bgpOIDtable{'snBgp4NeighborSummaryIp'};
		my $result_idx	= $session->get_table( -baseoid => $p_idxTbl );

		INDEXOID: foreach my $l_idxOID ( oid_lex_sort( keys( %{$result_idx} ) ) )
		{
			next if( $result_idx->{$l_idxOID} ne $peerIP );

			my $baseLength	= length( $bgpOIDtable{'snBgp4NeighborSummaryIp'} ) + 1;
			my $l_idx	= substr( $l_idxOID, $baseLength );
			$bgpPeer{'idxPrefix'} = $l_idx;

			if( $np->opts->{'debug'} )
			{
				print " BGP: Found prefix table index " . $bgpPeer{'idxPrefix'} .
				      " for peer $peerIP\n";
			}
		}
	}

	# PROG: First we need to pull the table to start indexing entries
	my $result	= $session->get_table( -baseoid => $bgpOIDtable{'bgp4V2PeerState'} );
	if( not defined($result) )
	{
		$session->close;
		np->plugin_exit( UNKNOWN, "Router doesn't support BGP4V2-MIB::bgp4V2PeerState" );
	}

	# -- Find specific peer information
	my $peerMatch = 0;
	PEEROID: foreach my $l_snmpOID ( oid_lex_sort( keys( %{$result}) ) )
	{
		next if( $l_snmpOID !~ /$bgpOID$/ ); # Find specific peer or skip entry.
		$peerMatch = 1;

		my $baseLength	= length( $bgpOIDtable{'bgp4V2PeerState'} ) + 1;
		my $l_vars	= substr( $l_snmpOID, $baseLength );

		my $l_instance	= substr( $l_vars, 0, 1);
		my $l_afinet	= substr( $l_vars, 2, 1);
		my $peerAFinetOID; # set below

		$bgpPeer{'instance'}	= $l_instance;  # Routing Instance
		$bgpPeer{'afinet'}	= $l_afinet;	# 1: ipv4, 2: ipv6 (as per INET-ADDRESS-MIB)
		$bgpPeer{'remoteAddrOID'} = _convert_IP_to_OID($np->opts->{'bgp'});

		if( $l_afinet == 1 )
		{
		    # -- IPv4 found
		    $peerAFinetOID = "1.4"; # ipv4, 4 entries following
		    $bgpPeer{'afinetOID'} = "1.4";

		    if( $l_vars =~ /^$l_instance.$peerAFinetOID/ )
		    {
			my @l_localaddrArr	= split( /\./, $l_vars, -1 );
			# LOOP: count is 3rd position to the 6th (4 octets)
			foreach ( 3 .. 6 )
			{
			    if( $_ == 6 )
			    {
				$bgpPeer{'localAddrOID'} .= $l_localaddrArr[$_];
			    } else {
				$bgpPeer{'localAddrOID'} .= $l_localaddrArr[$_] . ".";
			    }
			} #end:foreach
		    }
		}
		elsif ( $l_afinet == 2 )
		{
		    # == IPv6 found
		    $peerAFinetOID = "2.16"; # ipv6, 16 entries following
		    $bgpPeer{'afinetOID'} = "2.16";

		    if( $l_vars =~ /^$l_instance.$peerAFinetOID/ )
		    {
			my @l_localaddrArr	= split( /\./, $l_vars, -1 );
			$bgpPeer{'localAddr'}	= $np->opts->{'bgp'};  # -nistor: FIXME

			# LOOP: count is 2nd position to the 17th
			foreach ( 3 .. 18 )
			{
			    if( $_ == 18 )
			    {
				$bgpPeer{'localAddrOID'} .= $l_localaddrArr[$_];
			    } else {
				$bgpPeer{'localAddrOID'} .= $l_localaddrArr[$_] . ".";
			    }
			} # end:foreach
		    } # end: if l_vars
		} else {
			$np->plugin_exit( CRITICAL, "AFInet is not ipv4 or ipv6" );
		}
	}

	# SNMP: Create the latter half of the OID.
	my $s_subOID	= $bgpPeer{'instance'} . "." . $bgpPeer{'afinetOID'} . "." .
			  $bgpPeer{'localAddrOID'} . "." . $bgpPeer{'afinetOID'} . "." .
			  $bgpPeer{'remoteAddrOID'};

	# SNMP: Prep variables to be polled.
	my $p_bgpASN	= $bgpOIDtable{'bgpLocalAs'};
        my $p_State	= $bgpOIDtable{'bgp4V2PeerState'}        . "." . $s_subOID;
	my $p_Status	= $bgpOIDtable{'bgp4V2PeerAdminStatus'}  . "." . $s_subOID;
	my $p_LocalAS	= $bgpOIDtable{'bgp4V2PeerLocalAs'}      . "." . $s_subOID;
	my $p_RemoteAS	= $bgpOIDtable{'bgp4V2PeerRemoteAs'}     . "." . $s_subOID;
	my $p_errCode	 = $bgpOIDtable{'bgp4V2PeerLastErrorCodeReceived'}     . "." . $s_subOID;
	my $p_errSubCode = $bgpOIDtable{'bgp4V2PeerLastErrorSubCodeReceived'}  . "." . $s_subOID;
	#

	my @snmpoids;
	push( @snmpoids, $p_bgpASN, $p_State, $p_Status, $p_LocalAS, $p_RemoteAS);
	push( @snmpoids, $p_errCode, $p_errSubCode );


	my $p_Prefixes;	
	if( $peerAFinet == 4 )
	{
	    $p_Prefixes	= $bgpOIDtable{'snBgp4NeighborSummaryRouteReceived'} . "." . $bgpPeer{'idxPrefix'};
	    push( @snmpoids, $p_Prefixes );
	}

	if( $np->opts->{'verbose'} )
	{
		print "POLL: Attempting to poll state, admStatus, ASN, error Codes, etc..\n";
	}
	if( $np->opts->{'debug'} )
	{
		print "POLL: \@snmpoids -> " . join("\n  ", @snmpoids) . "\n";
	}

	my $s_result = $session->get_request( -varbindlist => \@snmpoids );

	if( not defined( $s_result ) )
	{
		$session->close;
		$np->plugin_exit( UNKNOWN, "BGP neighbor not configured ?" );
	} else {
		$session->close;
	}

	if( $s_result->{$p_State} eq "noSuchInstance" || not defined($s_result->{$p_State}) )
	{
		$np->plugin_exit( UNKNOWN, "BGP error: Does peer exist on this router?" );
	}

	$bgpPeer{'state'}	= $s_result->{$p_State};
	$bgpPeer{'stateName'}	= $bgpState{$s_result->{$p_State}};
	$bgpPeer{'admStatus'}	= $s_result->{$p_Status};
	$bgpPeer{'localAS'}	= $s_result->{$p_LocalAS} ?
				  $s_result->{$p_LocalAS} : $s_result->{$p_bgpASN};
	$bgpPeer{'remoteAS'}	= $s_result->{$p_RemoteAS};
	$bgpPeer{'errCode'}	= $s_result->{$p_errCode};
	$bgpPeer{'errSubCode'}	= $s_result->{$p_errSubCode};

	my $t_err		= sprintf("%02X %02X", $bgpPeer{'errCode'}, $bgpPeer{'errSubCode'}) ;
	$bgpPeer{'errText'}	= $bgpSubcodes{$t_err};

	if( $peerAFinet == 4 )
	{
		$bgpPeer{'prefixes'} = $s_result->{$p_Prefixes};
	}

	# $bgpPeer{'prefixes'}	= $s_result->{$p_Prefixes};

	if( $bgpPeer{'localAS'} == $bgpPeer{'remoteAS'} )
	{
		$bgpPeer{'type'} = "iBGP";
	} else {
		$bgpPeer{'type'} = "eBGP";
	}
}


# ------------------------------------------------------------------------------
sub _bgp_cisco
{
	if( $np->opts->{'debug'} )
	{
		print " SUB: Function _bgp_cisco processing ...\n";
	}
	#
	# NOTE: This function takes into account Cisco Routers (CISCO-BGP4-MIB)

	my $peerIP	= shift || $np->opts->{'bgp'};
	my $peerAFinet	= _ip_version($peerIP) ||
			  $np->plugin_exit( CRITICAL, "Not a valid IP address" );

	my $peerAFinetOID;
	if( $peerAFinet == 4 )
	{
		$peerAFinetOID = ".1.4"; # ipv4, 4 entries following
	} else {
		$peerAFinetOID = ".2.16"; # ipv6, 16 entries following
	}

	# SNMP: Prep variables to be polled.
	my $p_bgpASN	= $bgpOIDtable{'bgpLocalAs'};
        my $p_State	= $bgpOIDtable{'cbgpPeer2State'}        . $peerAFinetOID . "." . $bgpOID;
	my $p_Status	= $bgpOIDtable{'cbgpPeer2AdminStatus'}  . $peerAFinetOID . "." . $bgpOID;
	my $p_LocalAS	= $bgpOIDtable{'cbgpPeer2LocalAs'}      . $peerAFinetOID . "." . $bgpOID;
	my $p_RemoteAS	= $bgpOIDtable{'cbgpPeer2RemoteAs'}     . $peerAFinetOID . "." . $bgpOID;
	my $p_errCode	= $bgpOIDtable{'cbgpPeer2LastError'}    . $peerAFinetOID . "." . $bgpOID;
	my $p_errText	= $bgpOIDtable{'cbgpPeer2LastErrorTxt'} . $peerAFinetOID . "." . $bgpOID;

	my $p_Prefixes;	# Compute after we get the table entry for SAFI.
	my $p_SAFI;	# Compute after we get the table entry for SAFI.

	# SNMP: Cross reference prefixes table for peer type.
	my $p_PfxTbl	= $bgpOIDtable{'cbgpPeer2AcceptedPrefixes'} . $peerAFinetOID . "." . $bgpOID;
	my $result_pfx	= $session->get_table( -baseoid => $p_PfxTbl );
	if( keys( %{$result_pfx} ) == 1 ) # Count entries.
	{
		#  OID: Parse and set in hash.
		my $l_key	= each %{$result_pfx};
		my $l_afinet	= (split(/\./, substr( $l_key, -3 )))[0];
		my $l_safi	= substr( $l_key, -1 );

		$p_Prefixes	= $l_key;
		$bgpPeer{'safi'} = $l_safi;

		if( $np->opts->{'verbose'} )
		{
			print " BGP: session is " . $bgpAfi{$l_afinet} . "-" . $bgpSafi{$l_safi} . "\n";
		}
	} else {
		$np->plugin_exit( WARNING, "Multiple Prefix SAFI detected, bailing." );
	}

	my @snmpoids;
	push( @snmpoids, $p_bgpASN, $p_State, $p_Status, $p_LocalAS, $p_RemoteAS);
	push( @snmpoids, $p_errCode, $p_errText, $p_Prefixes );

	if( $np->opts->{'verbose'} )
	{
		print "POLL: Attempting to poll state, admStatus, ASN, error Codes, etc..\n";
	}
	if( $np->opts->{'debug'} )
	{
		print "POLL: \@snmpoids -> @snmpoids\n";
	}

	my $s_result = $session->get_request( -varbindlist => \@snmpoids );

	if( not defined( $s_result ) )
	{
		$session->close;
		$np->plugin_exit( UNKNOWN, "BGP neighbor not configured ?" );
	} else {
		$session->close;
	}

	if( $s_result->{$p_State} eq "noSuchInstance" || not defined($s_result->{$p_State}) )
	{
		$np->plugin_exit( UNKNOWN, "BGP error: Does peer exist on this router?" );
	}

	$bgpPeer{'state'}	= $s_result->{$p_State};
	$bgpPeer{'stateName'}	= $bgpState{$s_result->{$p_State}};
	$bgpPeer{'admStatus'}	= $s_result->{$p_Status};
	$bgpPeer{'localAS'}	= $s_result->{$p_LocalAS} ?
				  $s_result->{$p_LocalAS} : $s_result->{$p_bgpASN};
	$bgpPeer{'remoteAS'}	= $s_result->{$p_RemoteAS};
	$bgpPeer{'errCode'}	= $s_result->{$p_errCode};
	$bgpPeer{'errText'}	= $s_result->{$p_errText}; # Null if errCode == 00 00
	$bgpPeer{'prefixes'}	= $s_result->{$p_Prefixes};

	if( $bgpPeer{'localAS'} == $bgpPeer{'remoteAS'} )
	{
		$bgpPeer{'type'} = "iBGP";
	} else {
		$bgpPeer{'type'} = "eBGP";
	}
} # end:cisco


# ------------------------------------------------------------------------------
sub _bgp_juniper
{
	if( $np->opts->{'debug'} )
	{
		print " SUB: Function _bgp_juniper processing ...\n";
	}
	#
	# NOTE: This function takes into account Juniper routers (MX,T series).
	my $peerIP	= shift || $np->opts->{'bgp'};
	my $peerAFinet	= _ip_version($peerIP) ||
			  $np->plugin_exit( CRITICAL, "Not a valid IP address" );

	# PROG: First we need to pull the peerIndex table to match for
	#	routing instance #, local IP addr, remote IP addr [BGP neighbor]
	my $result	= $session->get_table( -baseoid => $bgpOIDtable{'jnxBgpM2PeerIndex'} );
	if( not defined($result) )
	{
		$session->close;
		$np->plugin_exit( UNKNOWN, "Router doesn't support BGP4-V2-MIB-JUNIPER::jnxBgpM2PeerIndex" );
	}

	# -- Find specific peer information
	my $peerMatch = 0;
	PEEROID: foreach my $l_snmpOID ( oid_lex_sort( keys( %{$result}) ) )
	{
		next if( $l_snmpOID !~ /$bgpOID$/ ); # Find specific peer or skip entry.
		$peerMatch = 1;

		my $baseLength  = length( $bgpOIDtable{'jnxBgpM2PeerIndex'} ) + 1;
		my $l_vars	= substr( $l_snmpOID, $baseLength );

		my $l_instance	= substr( $l_vars, 0, 1);
		my $l_afinet	= substr( $l_vars, 2, 1);
		my $l_index	= $result->{$l_snmpOID};

		$bgpPeer{'instance'}	= $l_instance;	# Routing Instance 0 = inet.
		$bgpPeer{'afinet'}	= $l_afinet;	# 1: ipv4, 2: ipv6 (as per INET-ADDRESS-MIB)
		$bgpPeer{'index'}	= $l_index;	# Index for pivoting another entry.
		$bgpPeer{'remoteAddrOID'} = _convert_IP_to_OID($np->opts->{'bgp'});


		if( $l_afinet == 1 )
		{
			# -- IPv4 found
			if( $l_vars =~ /^$l_instance.$l_afinet.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/ )
			{
				$bgpPeer{'localAddr'}		= "$1.$2.$3.$4";
				$bgpPeer{'localAddrOID'}	= "$1.$2.$3.$4";
			}
		}
		elsif ( $l_afinet == 2 )
		{
			# == IPv6 found
			if( $l_vars =~ /^$l_instance.$l_afinet/ )
			{
				my @l_localaddrArr	= split( /\./, $l_vars, -1 );
				$bgpPeer{'localAddr'}	= $np->opts->{'bgp'};

				# LOOP: count is 2nd position to the 17th (ipv6 is 16 sections)
				foreach ( 2 .. 17 )
				{
					if( $_ == 17 )
					{
					    $bgpPeer{'localAddrOID'} .= $l_localaddrArr[$_];
					} else {
					    $bgpPeer{'localAddrOID'} .= $l_localaddrArr[$_] . ".";
					}
				}
			}
		} else {
			print "ERROR ERROR ERROR ERROR\n";
			exit;
		}


		# SNMP: Create the latter half of the OID.
		my $s_subOID	= $bgpPeer{'instance'} . "." . $bgpPeer{'afinet'} . "." . $bgpPeer{'localAddrOID'} .
				  "." . $bgpPeer{'afinet'} . "." . $bgpPeer{'remoteAddrOID'};

		# SNMP: Create session and poll data.
		my $p_State	= $bgpOIDtable{'jnxBgpM2PeerState'} . "." . $s_subOID;
		my $p_Status	= $bgpOIDtable{'jnxBgpM2PeerStatus'} . "." . $s_subOID;	 # Admin Status
		my $p_LocalAS	= $bgpOIDtable{'jnxBgpM2PeerLocalAs'} . "." . $s_subOID;
		my $p_RemoteAS	= $bgpOIDtable{'jnxBgpM2PeerRemoteAs'} . "." . $s_subOID;
		my $p_Index	= $bgpOIDtable{'jnxBgpM2PeerIndex'} . "." . $s_subOID;
		my $p_errCode	= $bgpOIDtable{'jnxBgpM2PeerLastErrorReceived'} . "." . $s_subOID;
		my $p_errText	= $bgpOIDtable{'jnxBgpM2PeerLastErrorReceivedText'} . "." . $s_subOID;
		my $p_Prefixes;

		# SNMP: Cross reference prefixes table for peer type.
		my $p_PfxTbl	= $bgpOIDtable{'jnxBgpM2PrefixInPrefixesAccepted'} . "." .
				  $bgpPeer{'index'} . "." . $l_afinet;
		my $result_pfx	= $session->get_table( -baseoid => $p_PfxTbl );
		if( keys( %{$result_pfx} ) > 1  ) # Count entries.
		{
			$np->plugin_exit( WARNING, "Multiple Prefix SAFI detected, bailing." );
		} else {
			#  OID: Parse and set in hash.
			my $l_key	= each %{$result_pfx};
			my $l_safi	= substr( $l_key, -1 );
			my $l_afinet	= (split(/\./, substr( $l_key, -3 )))[0];


			$bgpPeer{'safi'} = $l_safi;
			$p_Prefixes	= $l_key;

			if( $np->opts->{'verbose'} )
			{
			    print " BGP: session is " . $bgpAfi{$l_afinet} . "-" . $bgpSafi{$l_safi} . "\n";
			}
		}

		my @snmpoids;
		push( @snmpoids, $p_State, $p_Status, $p_LocalAS, $p_RemoteAS);
		push( @snmpoids, $p_Index, $p_errCode, $p_errText, $p_Prefixes );

		if( $np->opts->{'verbose'} )
		{
			print "POLL: Attempting to poll state, admStatus, ASN, error Codes, etc..\n";
		}

		if( $np->opts->{'debug'} )
		{
			print "POLL: \@snmpoids -> @snmpoids\n";
		}

		my $s_result = $session->get_request( -varbindlist => \@snmpoids );

		if( not defined( $s_result ) )
		{
			$np->plugin_exit( UNKNOWN, " ERR: BGP neighbor not configured ?" );
		}

		if( $s_result->{$p_State} eq "noSuchInstance" || not defined($s_result->{$p_State}) )
		{
			$np->plugin_exit( UNKNOWN, " ERR: Does peer exist on this router ?" );
		}	

		# Index: jnxBgpM2PeerIndex, jnxBgpM2PrefixCountersAfi, jnxBgpM2PrefixCountersSafi

		$bgpPeer{'state'}	= $s_result->{$p_State};
		$bgpPeer{'stateName'}	= $bgpState{$s_result->{$p_State}};
		$bgpPeer{'localAS'}	= $s_result->{$p_LocalAS};
		$bgpPeer{'remoteAS'}	= $s_result->{$p_RemoteAS};
		$bgpPeer{'errCode'}	= $s_result->{$p_errCode};
		$bgpPeer{'errText'}	= $s_result->{$p_errText};
		$bgpPeer{'prefixes'}	= $s_result->{$p_Prefixes};
		if( $bgpPeer{'localAS'} == $bgpPeer{'remoteAS'} )
		{
			$bgpPeer{'type'} = "iBGP";
		} else {
			$bgpPeer{'type'} = "eBGP";
		}

	}

	if( $peerMatch == 0 )
	{
		$np->plugin_exit( UNKNOWN, "BGP error: Does peer exist on this router?" );
	}
}


# ------------------------------------------------------------------------------
# PROG: Output results.

if( $np->opts->{'verbose'} )
{
	print " BGP: " . $bgpPeer{'type'} . " neigh " . $bgpPeer{'IP'} .
	      ", AS " . $bgpPeer{'remoteAS'} . 
	      ", state(" . $bgpPeer{'state'} . "/" . $bgpPeer{'stateName'} . ")\n";
}

# ERR: Do some basic error checking.
if( defined($np->opts->{'bgplow'}) && defined($np->opts->{'bgphigh'}) )
{
	$np->plugin_exit( UNKNOWN, "Cannot define both bgplow and bgphigh values");
}

#  OK: If -r|--result is set, force OK if value is matched.
if( defined($np->opts->{'result'}) &&
           ($np->opts->{'result'}  == $bgpPeer{'state'}) )
{
	$np->plugin_exit( OK, "Peer " . $bgpPeer{'IP'} . " state " . $bgpPeer{'state'} .
			      "/" .  $bgpPeer{'stateName'} . ".  resCode: " .
			      $np->opts->{'result'} );
} elsif( defined($np->opts->{'result'}) &&
		($np->opts->{'result'}  != $bgpPeer{'state'}) )
{
	$np->plugin_exit( CRITICAL, "Peer " . $bgpPeer{'IP'} . " state " . $bgpPeer{'state'} .
			      "/" .  $bgpPeer{'stateName'} . ".  resCode: " .
			      $np->opts->{'result'} );
}

# BGP: State of connection results
if( ($bgpPeer{'state'} != 6 ) && ($bgpPeer{'admStatus'} == 1) )
{
	$np->plugin_exit( WARNING, "Peer " . $bgpPeer{'IP'} . " local admin shutdown" );
}
elsif ($bgpPeer{'state'} != 6 )
{
	$np->plugin_exit( CRITICAL, "Peer " . $bgpPeer{'IP'} . " down, err: " . $bgpPeer{'errText'} );
}

# BGP: Now check for prefixes, too low or too high?
if( $np->opts->{'debug'} )
{
	print " BGP: Receiving " . $bgpPeer{'prefixes'} . " prefixes from peer.\n";
	print "ALRT: warning threshold => " . $np->opts->{'warning'} . ", critical threshold => " .
	      $np->opts->{'critical'} . "\n";
}
if( defined($np->opts->{'bgplow'}) )
{
	if( defined($np->opts->{'critical'}) &&
		   ($np->opts->{'critical'}  >= $bgpPeer{'prefixes'})
	  ) #end:if
	{
		$np->plugin_exit( CRITICAL, $bgpPeer{'type'} . " AS" . $bgpPeer{'remoteAS'} .
				" " . $bgpPeer{'IP'} . " routes below " . $np->opts->{'critical'} .
				" (pfx " . $bgpPeer{'prefixes'} . ")" );
	}
	elsif( defined($np->opts->{'warning'}) &&
		      ($np->opts->{'warning'}  >= $bgpPeer{'prefixes'})
	     ) #end:if
	{
		$np->plugin_exit( WARNING, $bgpPeer{'type'} . " AS" . $bgpPeer{'remoteAS'} .
				" " . $bgpPeer{'IP'} . " routes below " . $np->opts->{'warning'} .
				" (pfx " . $bgpPeer{'prefixes'} . ")" );
	}
}

if( defined($np->opts->{'bgphigh'}) )
{
	if( defined($np->opts->{'critical'}) &&
		   ($np->opts->{'critical'}  <= $bgpPeer{'prefixes'} )
	  ) #end:if
	{
		$np->plugin_exit( CRITICAL, $bgpPeer{'type'} . " AS" . $bgpPeer{'remoteAS'} .
				" " . $bgpPeer{'IP'} . " routes above " . $np->opts->{'critical'} .
				" (pfx " . $bgpPeer{'prefixes'} . ")" );
	}
	elsif( defined($np->opts->{'warning'}) &&
		      ($np->opts->{'warning'}  <= $bgpPeer{'prefixes'})
	     ) #end:if
	{
		$np->plugin_exit( WARNING, $bgpPeer{'type'} . " AS" . $bgpPeer{'remoteAS'} .
				" " . $bgpPeer{'IP'} . " routes above " . $np->opts->{'warning'} .
				" (pfx " . $bgpPeer{'prefixes'} . ")" );
	}
}


# FINAL: Everything checks out perfectly.
if( not defined( $bgpPeer{'prefixes'} ) )
{
	$np->plugin_exit( OK, $bgpPeer{'type'} . " AS" . $bgpPeer{'remoteAS'}  . " " .
			      $bgpPeer{'IP'} . " is " . $bgpPeer{'stateName'} );
} else {
	$np->plugin_exit( OK, $bgpPeer{'type'} . " AS" . $bgpPeer{'remoteAS'}  . " " .
			      $bgpPeer{'IP'} . " is " . $bgpPeer{'stateName'} . ". " .
			      "pfx count " . $bgpPeer{'prefixes'} );
}

# EOF
#
