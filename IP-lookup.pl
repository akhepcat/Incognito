#!/usr/bin/perl -t
use Getopt::Long qw(:config no_ignore_case bundling pass_through);
use REST::Client;
use JSON;
use Socket qw(AF_INET AF_INET6 inet_pton inet_ntop inet_aton inet_ntoa);
use MIME::Base64;
#use Data::Dumper;
#use Scalar::Util qw(reftype);

my $username, $password, $ipaddr, $mask, $client, $headers, $query, $basequery;

my(%opt) = (
        mask		=> 0,
        maxmask		=> 16,
        user		=> "",
	pass		=> "",
	host		=> "localhost",
	port		=> 8993,	# Incognito IPSM API port default
        usage		=> 0,
	search		=> 0,
);

sub dec2ip ($) {
    join '.', unpack 'C4', pack 'N', shift;
}
sub ip2dec ($) {
    unpack N => pack CCCC => split /\./ => shift;
}

sub do_query($) {
	my $q = shift;

	$client->GET( $q, $headers );

	my $response = from_json($client->responseContent());
	my $count = $response->{'totalRecordCount'};

	if ($count > 0) {
		my $results = $response->{'results'}[0];
		my $svch = $results->{'serviceType'};
		my $sgh = $results->{'subnetGroup'};


		print " IP network: $results->{'name'}\n";
		print "Description: $results->{'description'}\n";
		print "subnetGroup: $sgh->{'name'}\n";
		print "serviceType: $svch->{'name'}\n";
		print "    IP type: $results->{'type'}\n";
		print "     status: $results->{'status'}\n";

		my $nname = $results->{'netname'};

		exit(0);
	}
}

sub usage {
        my($OPTIONS)= "\nUsage: $0 {options} [ip/subnet]\n";
        $OPTIONS .= "\t-m, --mask\t\t CIDR bitmask\n";
        $OPTIONS .= "\t-x, --maxmask\t\t upper limit of CIDR search (/$opt{maxmask} - /32)\n";
        $OPTIONS .= "\t-s, --search\t\t work around broken search API\n";
        $OPTIONS .= "\t-u, --username [user]\t authentication-user\n";
        $OPTIONS .= "\t-p, --password [pass]\t authentication-secret\n";
        $OPTIONS .= "\t-H, --host [hostname]\t API host (defaults to $opt{host})\n";
        $OPTIONS .= "\t-P, --port [port]\t API port (defaults to $opt{port})\n";
        $OPTIONS .= "\t-h, --help\t\t this help\n\n";
        die @_, $OPTIONS;
}

GetOptions( \%opt,
        "usage|help|u|h",
	"search|s",
        "mask|m=s",
        "maxmask|x=i",
        "username|u=s",
        "password|p=s",
        "port|P=i",
        "host|H=s",
) or usage("Invalid option");

usage("") if ($opt{usage});

if (defined($ARGV[0])) {
	$ipaddr = $ARGV[0];
} else {
	usage("missing: ip/subnet lookup");
}

if (defined($opt{username})) {
	$username = $opt{username};
} else {
	$username = $ENV{USER};
}
if (defined($opt{password})) {
	$password = $opt{password};
} else {
	$password = '';
}
if (defined($opt{mask})) {
	$mask=$opt{mask};
}

# Open up the connection and authenticate
$headers = {Accept => 'application/json', Authorization => 'Basic ' . encode_base64($username . ':' . $password)};
$client = REST::Client->new( host => "http://$opt{host}:$opt{port}", );
$basequery="/subnets?q=(networkAddress EQ";

if (defined($opt{search}) && ($opt{search} > 0)) {
	for ($mask=32;$mask>=$maxmask;$mask--) {
		my $network; $netmask;

		if ( $ipaddr=~ m/:/ ) {
			die "no searching in IPv6\n";
		} else {
			my $nm= ( (2 ** 32) - (2 ** (32 - $mask)) );
			$netmask = dec2ip($nm);
			my $ip = ip2dec ( $ipaddr );   #IP in an integer format
			$network = dec2ip( $ip & $nm);
		}

		$query= $basequery . qq| $network) AND (maskSize EQ $mask)|;
		do_query ($query);
	}

} else {
	if ($mask > 0) {
		$query = $basequery . qq| $ipaddr) AND (maskSize EQ $mask)|;
	} else {
		$query = $basequery . qq| $ipaddr)|;
	}

	do_query ($query);

	#if we get here, nothing was returned
	print "...nothing found\n";
}
