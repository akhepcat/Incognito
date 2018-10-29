#!/usr/bin/perl
BEGIN { $SIG{'__WARN__'} = sub { warn $_[0] if $DEBUG } }

#use strict;
use warnings;

use Net::IPv4Addr qw( :all );
use CGI;
use Getopt::Long qw(:config no_ignore_case bundling pass_through);
use REST::Client;
use JSON;
use MIME::Base64;
use Socket qw(AF_INET AF_INET6 inet_pton inet_ntop inet_aton inet_ntoa);
$|=1;

my $username, $password, $hostname, $port, $ipaddr, $mask, $client, $headers, $found, $CallingURI, $query, $basequery;

## site customizable

$username = '';
$password = '';
$hostname = 'localhost';
$port = 8993;
$CallingURI = '/IP-lookup.html';

### End of customizations


$found = 0;

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
	        print "<pre>\n";
		print " IP network: $results->{'name'}\n";
		print "Description: $results->{'description'}\n";
		print "subnetGroup: $sgh->{'name'}\n";
		print "serviceType: $svch->{'name'}\n";
		print "    IP type: $results->{'type'}\n";
		print "     status: $results->{'status'}\n";
		print "RIR netname: $results->{'netname'}\n" unless ( $results->{'type'} =~ m/PRIVATE/ );
	        $found = 1;
	}
}

my $CGIquery = new CGI;
my $ipaddr  = $CGIquery->param('ipaddr');
$ipaddr =~ s/[^0-9a-f.:]//g if length($ipaddr);

my $actionurl = $ENV{'SCRIPT_URL'};
$actionurl =~ s/&/&amp;/g if length($actionurl);

print $CGIquery->header;
print << "EOF";
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd" >
<html>
<head> 
   <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-15">
   <title>IP Lookup</title>
   <style>
     <!--
       body {
         background-color: white;
         color: black;
       }
     -->
   </style>
</head>
<body>
EOF

# Open up the connection and authenticate
$headers = {Accept => 'application/json', Authorization => 'Basic ' . encode_base64($username . ':' . $password)};
$client = REST::Client->new( host => "http://$hostname:$port", );

if (! length($ipaddr) ) {
        print "Empty IP address supplied\n";
        print  "<!-- '",$CGIquery->param('ipaddr'),"' --><br>\n";

} else {
    $basequery="/subnets?q=(networkAddress EQ";

    if ( ipv4_chkip($ipaddr) ) {
        print "<pre>Checking IPv4 address &lt;$ipaddr&gt;</pre>\n";

	for ($mask=32;$mask>=16;$mask--) {
		my $network; $netmask;
		my $nm= ( (2 ** 32) - (2 ** (32 - $mask)) );
		$netmask = dec2ip($nm);
		my $ip = ip2dec ( $ipaddr );   #IP in an integer format
		$network = dec2ip( $ip & $nm);
		$query= $basequery . qq| $network) AND (maskSize EQ $mask)|;
		do_query ($query);
		last if ($found);
        }
        
    } else {
    	#working around for lack of IPv6 searching
    	print "<strong>Warning: IPv6 address searching is currently broken.</strong><br>\n";
        print "<pre>Checking IPv6 network &lt;$ipaddr&gt;</pre>\n";

        $query = $basequery . qq| $ipaddr)|;
	do_query ($query);
    }

    print "...nothing found\n" unless $found;
}

print <<"EOF";
<br>
<hr>
<a href="$CallingURI">return...</a>
</body>
</html>
EOF
