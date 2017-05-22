#!/usr/bin/perl
#
# Copyright (C) 2017 Jon Nistor
#
# --
# Author:	Jon Nistor (nistor@snickers.org)
# Purporse:	Monitoring Plugin to check for Cisco WLC controllers.
#		Count the number of clients on the controller / per SSID.
# MIB:		Based on CISCO-LWAPP-WLAN-MIB
# Vendors:	Cisco
#
# Version:	0.02
#
# History:
#
#  2017-05-21	0.01	Initial
#  2017-06-22	0.02	Added IPv6 support.
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

use Monitoring::Plugin;
use Monitoring::Plugin::Getopt;
use Monitoring::Plugin::Threshold;
use Net::SNMP qw(oid_lex_sort);
use Socket qw( :DEFAULT );
use Socket6;
#
use strict;
use constant VERSION => '0.01';

$SIG{'ALRM'} = sub {
	plugin_exit( UNKNOWN, "Plugin took too long to complete (alarm)");
};


# -----------------------------------------------------------------------------
# PROG: Build initial object
my $np = Monitoring::Plugin->new(
	shortname => "",
	usage	  => "Usage: %s [-H|--host <controller>] [-P|--snmpver <2|3>]" .
		     " [-s|--snmpcomm <comm>] [-d|--debug] [-v|--verbose]" .
		     " [-n|--ssid <SSIDname>] [-a|--all]" .
		     " [-w|--warning <clientCnt>] [-c|--critical <clientCnt>]" .
		     " [-4] [-6]" .
		     "",
	version	  => VERSION,
	url	  => 'https://github.com/nistorj/monitoring-plugins',
	blurb	  => 'Check wlan client counts (total/per ssid)',
);

# -----------------------------------------------------------------------------
# PROG: Building arguments list, usage/help documentation
#
#	-a | --all	Flag to enable counting of all clients
#	-d | --debug	Enable debug output (not to be used in production)
#	-H | --host	Hostname of Cisco Wireless Controller
#	-n | --ssid	Specific SSID to match on
#	-r | --result	Integer value of answer (clients)
#	-s | --snmpcomm	SNMP community of the WLC.
#	-P | --snmpver	SNMP version to use in polling
#	-v | --verbose	Provide a little more output

$np->add_arg(
	spec	 => 'all|a',
	help	 => '-a, --all Enable total client count',
	default	 => undef,
	required => 0
);

$np->add_arg(
	spec	 => 'debug|d',
	help	 => '-d, --debug output',
	default	 => undef,
	required => 0
);

$np->add_arg(
	spec	 => 'ssid|n=s',
	help	 => '-n, --ssid=SSIDname WLAN name to match',
	default	 => undef,
	required => 0
);

$np->add_arg(
	spec	 => 'host|H=s',
	help	 => '-H, --host=HOSTNAME of Cisco wireless controller to poll',
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
	spec	 => 'verbose|v',
	help	 => '-v, --verbose display more information',
	default	 => undef,
	required => 0
);

$np->add_arg(
	spec	 => 'clienthigh|A',
	help	 => '-A, --clienthigh alert if session count is above value',
	default	 => undef,
	required => 0
);

$np->add_arg(
	spec	 => 'clientlow|B',
	help	 => '-B, --clientlow alert if session count drops below value',
	default	 => undef,
	required => 0
);

$np->add_arg(
	spec	 => 'v4|4',
	help	 => '-4, --v4 Force polling over IPv4',
	default	 => undef,
	required => 0
);

$np->add_arg(
	spec	 => 'v6|6',
	help	 => '-6, --v6 Force polling over IPv6',
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
	print " OPT:   Passing arguments.. \n";
	print " OPT:       host: " . $np->opts->{'host'} . "\n";
	print " OPT:    snmpver: " . $np->opts->{'snmpver'} . "\n";
	print " OPT:  clientlow: " . $np->opts->{'clientlow'} . "\n";
	print " OPT: clienthigh: " . $np->opts->{'clienthigh'} . "\n";
	print " OPT:     result: " . $np->opts->{'result'} . "\n";
	print " OPT:        all: " . $np->opts->{'all'} . "\n";
	print " OPT:       ssid: " . $np->opts->{'ssid'} . "\n";
	print " OPT:         v4: " . $np->opts->{'v4'} . "\n";
	print " OPT:         v6: " . $np->opts->{'v6'} . "\n";
	print " OPT:       warn: " . $np->opts->{'warning'} . "\n";
	print " OPT:       crit: " . $np->opts->{'critical'} . "\n";
}

if( defined($np->opts->{'clientlow'}) && defined($np->opts->{'clienthigh'}) )
{
	$np->plugin_exit( UNKNOWN, "Cannot define both clientlow and " .
				   " clienthigh values.");
}

if( defined($np->opts->{'all'}) && defined($np->opts->{'ssid'}) )
{
	$np->plugin_exit( UNKNOWN, "Cannot define both ssid name and all.");
}

# -----------------------------------------------------------------------------
# SNMP: mib:oid information

my %wlanOIDtable	= (
	#----------------------------------------------------------------------
	# NOTE: Using CISCO-LWAPP-WLAN-MIB information
	'sysObjectID'			=> '1.3.6.1.2.1.1.2.0',

	'cLWlanRowStatus'		=> '1.3.6.1.4.1.9.9.512.1.1.1.1.2',
	'cLWlanProfileName'		=> '1.3.6.1.4.1.9.9.512.1.1.1.1.3',
	'cLWlanSsid'			=> '1.3.6.1.4.1.9.9.512.1.1.1.1.4',

	# MIB: AIRESPACE-WIRELESS-MIB
	'bsnDot11EssNumberOfMobileStations' => '1.3.6.1.4.1.14179.2.1.1.1.38',
);

my %wlan;

# -----------------------------------------------------------------------------
# PROG: Construct SNMP session information.


my $addrHost	= $np->opts->{'host'};
my @addrInfo	= getaddrinfo($addrHost, 'snmp', AF_UNSPEC, SOCK_STREAM, 'udp');
$np->plugin_exit( UNKNOWN, "Cannot resolve $addrHost" ) unless( scalar(@addrInfo) >= 5 );

if( ( ($addrInfo[0] == AF_INET6) &&
      (not defined($np->opts->{'v4'})) ) || defined($np->opts->{'v6'}) )
{
	$np->opts->{'snmptransport'} = "udp6";
} 
elsif( ( ($addrInfo[0] == AF_INET) &&
       (not defined($np->opts->{'v6'})) ) || defined($np->opts->{'v4'}) )
{
	$np->opts->{'snmptransport'} = "udp";
} else {
	$np->plugin_exit( UNKNOWN, "Address family cann't resolve $addrHost" );
}

# DBG: What transport method?
if( $np->opts->{'debug'} )
{
	print "SNMP: Transport will be " . $np->opts->{'snmptransport'} . "\n";
}
	


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
	-domain		=> $np->opts->{'snmptransport'},
	-debug		=> 0x00,
	@snmpopts
);

if( not defined($session) )
{
	$np->plugin_exit( CRITICAL, "SNMP session check failed: " . $error );
	exit(1);
}



# -----------------------------------------------------------------------------
# PROG: Start process of polling WLAN/SSID information
if( $np->opts->{'ssid'} )
{
	_wlan_ssid();
}
elsif ( $np->opts->{'all'} )
{
	_wlan_clientCount();
} else {
	$np->plugin_exit( UNKNOWN, "Need to specify either 'all' or SSID wlan");
}


# VARS: Set a few vars.
my $result;
my @snmpoids;

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
sub _wlan_ssid
{
	if( $np->opts->{'debug'} )
	{
		my $this_subs_name = (caller(0))[3];
		print " SUB: Function $this_subs_name processing ...\n";
	}
	#
	if( not defined($np->opts->{'ssid'}) )
	{
		$np->plugin_exit( UNKNOWN, "No SSID wlan has been defined" );
	}
	my $e_ssid	= shift || $np->opts->{'ssid'};
	if( $e_ssid !~ /[a-z0-9]/i )
	{
		print "WLAN: $e_ssid\n";
		$np->plugin_exit( CRITICAL,
				  "Invalid character detected in wlane" );
	}

	# PROG: First we need to pull the cLWlanSsid table
	#
	my $result	= $session->get_table( -baseoid =>
					$wlanOIDtable{'cLWlanSsid'} );
	if( not defined($result) )
	{
		$session->close;
		$np->plugin_exit( UNKNOWN, "Wireless Controller doesn't " .
			 "support CISCO-LWAPP-WLAN-MIB::cLWlanSsid" );
	}

	# -- Find specific peer information
	my $ssidMatch = 0;
	SSIDOID: foreach my $l_snmpOID ( oid_lex_sort( keys( %{$result}) ) )
	{
		next if( $result->{$l_snmpOID} ne $e_ssid );

		$ssidMatch = 1;

		my $baseLength  = length( $wlanOIDtable{'cLWlanSsid'} ) + 1;
		my $l_vars	= substr( $l_snmpOID, $baseLength );
		my $l_index	= substr( $l_vars, 0 );

		my $s_ssid	= $result->{$l_snmpOID};


		$wlan{'ssid'}{'name'}	= $e_ssid;
		$wlan{'ssid'}{'count'}++;
		push( @{$wlan{'ssid'}{'index'}}, $l_index );

		if( $np->opts->{'debug'} )
		{
			print "WLAN: added $e_ssid, index id $l_index\n";
		}
	}

	if( $ssidMatch == 0 )
	{
		$np->plugin_exit( UNKNOWN, "WLAN error: Does ssid exist ".
					   "on this controller?" );
	}

	if( $np->opts->{'verbose'} )
	{
		print "WLAN: All instances found idx: " .
		      "@{$wlan{'ssid'}{'index'}}" . "\n";
	}

	foreach my $x_index ( sort @{$wlan{'ssid'}{'index'}} )
	{
		# PROG: check against each index number to build hash info.
		_wlan_clientCount($x_index);

	} # end:foreach
}

sub _wlan_clientCount
{
	if( $np->opts->{'debug'} )
	{
		my $this_subs_name = (caller(0))[3];
		print " SUB: Function $this_subs_name processing ...\n";
	}

	my $o_index	= shift || 0;

	# --
	my $n_result = $session->get_table( -baseoid =>
			$wlanOIDtable{'bsnDot11EssNumberOfMobileStations'} );

	if( not defined($n_result) )
	{
	    $session->close;
	    $np->plugin_exit( UNKNOWN, "Wireless controler doesn't support" .
		" AIRESPACE-WIRELESS-MIB::bsnDot11EssNumberOfMobileStations" );
	}

	# -- Find specific client count per SSID
	CNTOID: foreach my $l_snmpOID ( oid_lex_sort( keys( %{$n_result}) ) )
	{

		my $baseLength	= length( $wlanOIDtable{'bsnDot11EssNumberOfMobileStations'} ) + 1;
		my $l_vars	= substr( $l_snmpOID, $baseLength );
		my $l_index	= substr( $l_vars, 0 );

		next if( $o_index && ( $o_index != $l_index ) );

		# PROG: Insert results of client counts
		$wlan{'clients'}{'total'} += $n_result->{$l_snmpOID};

		if( $np->opts->{'debug'} )
		{
			print " CNT: instance $l_index with " .
				$n_result->{$l_snmpOID} . " clients.\n";
		}
	} # END:foreach
}


# ------------------------------------------------------------------------------
# PROG: Output results.
#
if( $np->opts->{'verbose'} )
{
	print " DBG: Processing output\n";
}

my $userCount	= $wlan{'clients'}{'total'};
my $o_result	= $np->opts->{'result'};

# O/RESULT: If _RESULT_ option is matched, force OK.
if( defined($np->opts->{'result'}) &&
	   ($np->opts->{'result'}  == $userCount) )
{
	$np->plugin_exit( OK, "Client count $userCount" );
} elsif (defined($np->opts->{'result'}) &&
		($np->opts->{'result'}  != $userCount) )
{
	$np->plugin_exit( CRITICAL, "Client count $userCount, " .
				    "expecting $o_result" );
}

# O/NBRLOW
if( defined($np->opts->{'clientlow'}) )
{
	my $x_crit	= $np->opts->{'critical'};
	my $x_warn	= $np->opts->{'warning'};

	if( defined($np->opts->{'critical'}) &&
		   ($np->opts->{'critical'}  >= $userCount)
	  ) #end:if
	{
		$np->plugin_exit( CRITICAL, "Client count $userCount, low " .
					    "critical threshold $x_crit");
	}
	elsif( defined($np->opts->{'warning'}) &&
		      ($np->opts->{'warning'}  >= $userCount)
	      ) #end:if
	{
		$np->plugin_exit( WARNING, "Client count $userCount, low " .
					   "warning threshold $x_warn");
	}
}

# O/NBRHIGH
if( defined($np->opts->{'clienthigh'}) )
{
	my $x_crit	= $np->opts->{'critical'};
	my $x_warn	= $np->opts->{'warning'};

	if( defined($np->opts->{'critical'}) &&
		   ($np->opts->{'critical'}  <= $userCount)
	  ) #end:if
	{
		$np->plugin_exit( CRITICAL, "Client count $userCount, high " .
					    "critical threshold $x_crit");
	}
	elsif( defined($np->opts->{'warning'}) &&
		      ($np->opts->{'warning'}  <= $userCount)
	      ) #end:if
	{
		$np->plugin_exit( WARNING, "Client count $userCount, high " .
					   "warning threshold $x_warn");
	}
}

if( $np->opts->{'ssid'} )
{
	$np->plugin_exit( OK, "SSID " . $np->opts->{'ssid'} .
			      " client count $userCount" );
} else {
	$np->plugin_exit( OK, "Client count $userCount" );
}


# EOF
#
