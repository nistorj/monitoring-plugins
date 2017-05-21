#!/usr/bin/perl
#
# Copyright (C) 2017 Jon Nistor
#
# --
# Author:	Jon Nistor (nistor@snickers.org)
# Purporse:	Monitoring Plugin to check for EIGRP neighbour counts, alert
#		if the neighbour count is above or below a threshold.
# MIB:		Based on CISCO-EIGRP-MIB
# Vendors:	Cisco
#
# Version:	0.01
#
# History:
#
#  2017-05-20	0.01	Initial
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
use Net::IP;
use Net::SNMP qw(oid_lex_sort);
use Socket;
#
use strict;
use constant VERSION => '0.01';

$SIG{'ALRM'} = sub {
	plugin_exit( UNKNOWN, "Plugin took too long to complete (alarm)");
};


# -----------------------------------------------------------------------------
# PROG: Build initial object
my $np = Monitoring::Plugin->new(
	shortname	=> "",
	usage		=> "Usage: %s [-H|--host <router>] [-P|--snmpver <2|3>]" .
			   " [-s|--snmpcomm <comm>] [-d|--debug] [-v|--verbose]" .
			   " [-i|--ifindex <ifIndex>] [-a|--asnum <AS number>]" .
			   " [-n|--vpn <vrfName>]" .
			   " [-w|--warning <nbcCount>] [-c|--critical <nbrCount>]" .
			   "",
	version		=> VERSION,
	url		=> 'https://github.com/nistorj/monitoring-plugins',
	blurb		=> 'Check EIGRP neighbor counts',
);

# -----------------------------------------------------------------------------
# PROG: Building arguments list, usage/help documentation
#
#	-a | --asn	Autonomous System Number for EIGRP instance
#	-d | --debug	Enable debug output (not to be used in production)
#	-H | --host	Hostname of EIGRP router to poll
#	-i | --ifindex	SNMP ifIndex entry (TODO)
#	-n | --vpn	Find AS of VPN name, if found within vpn. (vrf)
#	-r | --result	Integer value of answer
#	-s | --snmpcomm	SNMP community of the router
#	-P | --snmpver	SNMP version to use in polling
#	-v | --verbose	Provide a little more output
#	-A | --nbrhigh	true:false alert on session count above.
#	-B | --nbrlow	true:false alert on session count below.

$np->add_arg(
	spec	 => 'asn|a=s',
	help	 => '-a, --asn=number Autonomous System Number',
	default	 => undef,
	required => 0
);

$np->add_arg(
	spec	 => 'ifindex|i=s',
	help	 => '-i, --ifindex=snmpIfIndex of EIGRP peer interface (TODO)',
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
	spec	 => 'vpn|n=s',
	help	 => '-n, --vpn=vpnName of EIGRP router instance (vrf)',
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
	spec	 => 'verbose|v',
	help	 => '-v, --verbose display more information',
	default	 => undef,
	required => 0
);

$np->add_arg(
	spec	 => 'nbrhigh|A',
	help	 => '-A, --nbrhigh alert if session count is above value',
	default	 => undef,
	required => 0
);

$np->add_arg(
	spec	 => 'nbrlow|B',
	help	 => '-B, --nbrlow alert if session count drops below value',
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
	print " OPT:  ifindex: " . $np->opts->{'ifindex'} . "\n"; 
	print " OPT:     host: " . $np->opts->{'host'} . "\n";
	print " OPT:  snmpver: " . $np->opts->{'snmpver'} . "\n";
	print " OPT:   nbrlow: " . $np->opts->{'nbrlow'} . "\n";
	print " OPT:  nbrhigh: " . $np->opts->{'nbrhigh'} . "\n";
	print " OPT:   result: " . $np->opts->{'result'} . "\n";
	print " OPT:      asn: " . $np->opts->{'asn'} . "\n";
	print " OPT:      vpn: " . $np->opts->{'vpn'} . "\n";
	print " OPT:     warn: " . $np->opts->{'warning'} . "\n";
	print " OPT:     crit: " . $np->opts->{'critical'} . "\n";
}

if( defined($np->opts->{'nbrlow'}) && defined($np->opts->{'nbrhigh'}) )
{
	$np->plugin_exit( UNKNOWN, "Cannot define both nbrlow and nbrhigh values");
}

if( (not defined($np->opts->{'asn'})) && (not defined($np->opts->{'vpn'})) )
{
	$np->plugin_exit( UNKNOWN, "Must define either VPN/VRF or ASN");
}


# -----------------------------------------------------------------------------
# SNMP: mib:oid information

my %eigrpOIDtable	= (
	# -----------------------------------------------------------------------------
	# NOTE: Using CISCO-EIGRP-MIB information
	'sysObjectID'			=> '1.3.6.1.2.1.1.2.0',

	'cEigrpVpnName'			=> '1.3.6.1.4.1.9.9.449.1.1.1.1.2',
	'cEigrpNbrCount'		=> '1.3.6.1.4.1.9.9.449.1.2.1.1.2',
	'cEigrpInputQDrops'		=> '2.3.6.1.4.1.9.9.449.1.2.1.1.14',
	'cEigrpPeerAddrType'		=> '1.3.6.1.4.1.9.9.449.1.4.1.1.2',
	'cEigrpPeerIfIndex'		=> '1.3.6.1.4.1.9.9.449.1.4.1.1.4',
	'cEigrpPeerCount'		=> '1.3.6.1.4.1.9.9.449.1.5.1.1.3',
);

my %eigrpAfi	= (
	  1 => 'ipv4',
	  2 => 'ipv6'
);

my %eigrp;

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

if( not defined($session) )
{
	$np->plugin_exit( CRITICAL, "SNMP session check failed: " . $error );
	exit(1);
}



# -----------------------------------------------------------------------------
# PROG: Start process of polling EIGRP information
if( $np->opts->{'vpn'} )
{
	_eigrp_vpn();
}

if( $np->opts->{'asn'} )
{
	if( ( $np->opts->{'asn'} > 0 ) && ( $np->opts->{'asn'} < 65536 ) )
	{
	    _eigrp_nbrCount(0,$np->opts->{'asn'});
	} else {
	    $np->plugin_exit( CRITICAL, "AS Number invalid" );
	}
}

# CHECK: Validate router type is right
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
sub _eigrp_vpn
{
	if( $np->opts->{'debug'} )
	{
		my $this_subs_name = (caller(0))[3];
		print " SUB: Function $this_subs_name processing ...\n";
	}
	#
	# NOTE: This function takes into account Juniper routers (MX,T series).
	if( not defined($np->opts->{'vpn'}) )
	{
		$np->plugin_exit( UNKNOWN, "No VPN name has been defined" );
	}
	my $e_vpnName	= shift || $np->opts->{'vpn'};
	if( $e_vpnName !~ /[a-z0-9]/i )
	{
		print "VPN: $e_vpnName\n";
		$np->plugin_exit( CRITICAL, "Invalid character detected in VPN name" );
	}

	# PROG: First we need to pull the cEigrpVpnName table to find the matching names.
	#
	my $result	= $session->get_table( -baseoid => $eigrpOIDtable{'cEigrpVpnName'} );
	if( not defined($result) )
	{
		$session->close;
		$np->plugin_exit( UNKNOWN, "Router doesn't support CISCO-EIGRP-MIB::cEigrpVpnName" );
	}

	# -- Find specific peer information
	my $peerMatch = 0;
	PEEROID: foreach my $l_snmpOID ( oid_lex_sort( keys( %{$result}) ) )
	{
		next if( $result->{$l_snmpOID} ne $e_vpnName );

		$peerMatch = 1;

		my $baseLength  = length( $eigrpOIDtable{'cEigrpVpnName'} ) + 1;
		my $l_vars	= substr( $l_snmpOID, $baseLength );
		my $l_instance	= substr( $l_vars, 0 );

		my $s_vpnName	= $result->{$l_snmpOID};


		$eigrp{'vpn'}{'name'}	= $e_vpnName;
		$eigrp{'vpn'}{'count'}++;
		push( @{$eigrp{'vpn'}{'instance'}}, $l_instance );

		if( $np->opts->{'debug'} )
		{
			print " VPN: added #e_vpnName, instance id $l_instance\n";
		}
		
	}

	if( $peerMatch == 0 )
	{
		$np->plugin_exit( UNKNOWN, "EIGRP error: Does vpnName exist on this router?" );
	}

	if( $np->opts->{'verbose'} )
	{
		print " VPN: All instances found idx: " . "@{$eigrp{'vpn'}{'instance'}}" . "\n";
	}

	foreach my $x_instance ( sort @{$eigrp{'vpn'}{'instance'}} )
	{
		# PROG: check against each instance number to build hash info.
		_eigrp_nbrCount($x_instance);

	} # end:foreach

}

sub _eigrp_nbrCount
{
	if( $np->opts->{'debug'} )
	{
		my $this_subs_name = (caller(0))[3];
		print " SUB: Function $this_subs_name processing ...\n";
	}

	my $o_instance	= shift || 0;
	my $o_asn	= shift || 0;

	# --
	# -- Once instance number is gathered, query for ASN#/Count based on cEigrpNbrCount.
	my $n_result = $session->get_table( -baseoid => $eigrpOIDtable{'cEigrpNbrCount'} );

	if( not defined($n_result) )
	{
		$session->close;
		$np->plugin_exit( UNKNOWN, "Router doesn't support CISCO-EIGRP-MIB::cEigrpNbrCount" );
	}

	# -- Find specific neighbour information/count
	CNTOID: foreach my $l_snmpOID ( oid_lex_sort( keys( %{$n_result}) ) )
	{

		my $baseLength	= length( $eigrpOIDtable{'cEigrpNbrCount'} ) + 1;
		my $l_vars	= substr( $l_snmpOID, $baseLength );
		my $l_instance	= substr( $l_vars, 0, index($l_vars, "."));
		my $l_asn	= substr( $l_vars, rindex( $l_vars, '.' ) + 1 );

		next if( $o_instance && ( $o_instance != $l_instance ) );
		next if( $o_asn      && ( $o_asn != $l_asn ) );

		push( @{$eigrp{'asn'}{'asnum'}}, $l_asn );
		push( @{$eigrp{'asn'}{'instance'}}, $l_instance );

		# PROG: ASN is unique remove any duplicates.
		# my @asn_tmp = keys { map { $_ => 1 } @{$eigrp{'asn'}{'asnum'}} };
		my %ASKEYS	= map { $_, 1 } @{$eigrp{'asn'}{'asnum'}};
		my @asn_tmp	= keys %ASKEYS;
		@{$eigrp{'asn'}{'asnum'}} = @asn_tmp;

		# PROG: Insert results of neighbour counts
		$eigrp{'asn'}{'nbrCount'}{'total'} += $n_result->{$l_snmpOID};
		$eigrp{'asn'}{'nbrCount'}{'instance'}{$l_instance} += $n_result->{$l_snmpOID};

		if( $np->opts->{'debug'} )
		{
			print " CNT: instance $l_instance with " . $n_result->{$l_snmpOID} .
			      " neighbours.\n";
		}
	} # END:foreach

	if( not defined($eigrp{'asn'}{'asnum'}) )
	{
		$np->plugin_exit( UNKNOWN, "AS " . $np->opts->{'asn'} . " does not exist");
	}
}


# ------------------------------------------------------------------------------
# PROG: Output results.
#
if( $np->opts->{'verbose'} )
{
	print " DBG: Processing output\n";
}

my $nbrCount	= $eigrp{'asn'}{'nbrCount'}{'total'};
my $asnum	= join(',', @{$eigrp{'asn'}{'asnum'}});
my $o_result	= $np->opts->{'result'};

# O/RESULT: If _RESULT_ option is matched, force OK.
if( defined($np->opts->{'result'}) &&
	   ($np->opts->{'result'}  == $nbrCount) )
{
	$np->plugin_exit( OK, "Peer count $nbrCount" );
} elsif (defined($np->opts->{'result'}) &&
		($np->opts->{'result'}  != $nbrCount) )
{
	$np->plugin_exit( CRITICAL, "Peer count $nbrCount, expecting $o_result" );
}

# O/NBRLOW
if( defined($np->opts->{'nbrlow'}) )
{
	my $x_crit	= $np->opts->{'critical'};
	my $x_warn	= $np->opts->{'warning'};

	if( defined($np->opts->{'critical'}) &&
		   ($np->opts->{'critical'}  >= $nbrCount)
	  ) #end:if
	{
		$np->plugin_exit( CRITICAL, "Peer count $nbrCount, low critical ".
					    "threshold $x_crit");
	}
	elsif( defined($np->opts->{'warning'}) &&
		      ($np->opts->{'warning'}  >= $nbrCount)
	      ) #end:if
	{
		$np->plugin_exit( WARNING, "Peer count $nbrCount, low warning ".
					   "threshold $x_warn");
	}
}

# O/NBRHIGH
if( defined($np->opts->{'nbrhigh'}) )
{
	my $x_crit	= $np->opts->{'critical'};
	my $x_warn	= $np->opts->{'warning'};

	if( defined($np->opts->{'critical'}) &&
		   ($np->opts->{'critical'}  <= $nbrCount)
	  ) #end:if
	{
		$np->plugin_exit( CRITICAL, "Peer count $nbrCount, high critical ".
					    "threshold $x_crit");
	}
	elsif( defined($np->opts->{'warning'}) &&
		      ($np->opts->{'warning'}  <= $nbrCount)
	      ) #end:if
	{
		$np->plugin_exit( WARNING, "Peer count $nbrCount, high warning ".
					   "threshold $x_warn");
	}
}

$np->plugin_exit( OK, "AS$asnum Peer count $nbrCount" );


# EOF
#
