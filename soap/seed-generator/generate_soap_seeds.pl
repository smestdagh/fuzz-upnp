#!/usr/bin/perl

=pod

=head1 NAME

generate_soap_seeds.pl

=head1 SYNOPSIS

This script will check which UPnP services are present in the given root
device description, download the SCPD for each of them if needed, and
generate SOAP requests for each action in each service.

Each generated request is saved to a separate file. Requests are generated
with empty arguments, and with random arguments.

Example:

./generate_soap_seeds.pl rootDesc.xml http://localhost:12345

=head1 LICENSE

Copyright (c) 2019 Steven Mestdagh

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

=cut

use strict;
use warnings;

use File::Basename;
use XML::XPath;
use XML::XPath::XMLParser;
use SOAP::Lite;

use List::Util qw[min max];
use Algorithm::Loops qw[NestedLoops];
use Math::GMPz qw/zgmp_randinit_mt zgmp_randseed_ui zgmp_urandomb_ui/;
use MIME::Base64;

my $debug = 1;

# random number initialisation
my $state = zgmp_randinit_mt();
zgmp_randseed_ui($state, time());

# get command line arguments
if (@ARGV != 2) {
	die "Usage: script inputfile server-root-URL\n"
}
my $descr_filename  = $ARGV[0];
my $server_root_url = $ARGV[1];

# default number of seeds to generate (per action, should be >= 1)
my $numseeds = 3;

# initialize global variables
my $services = [];
my $seedcounter = 0;

# abbreviations for services to use in filenames
my $short_svc_names = {
	'Layer3Forwarding'		=> 'L3F',
	'WANIPConnection'		=> 'WANIPC',
	'WANCommonInterfaceConfig'	=> 'WANCfg',
	'WANIPv6FirewallControl'	=> 'WANIP6FC',
	'DeviceProtection'		=> 'DP',
	'tvcontrol:1'			=> 'tvcontrol',
	'tvpicture:1'			=> 'tvpicture',
};

# start XML parser for the root device description
my $xp = XML::XPath->new(filename => $descr_filename);
# find all services
print "Getting all services in the root device description\n\n";
my $nodeset = $xp->find('//service');

# save service info in array of hashes
my $i = 0;
foreach my $node ($nodeset->get_nodelist) {
    print "Service $i\n\n";

    $services->[$i] = {};
    for my $c ($node->getChildNodes) {
	my $elName  = $c->getLocalName;
	my $elValue = $c->string_value;
	$services->[$i]->{$elName} = $elValue;
	print "$elName: $elValue\n";
    }

    # save a shorter name for use in seed filenames later
    $services->[$i]->{'shortname'} = $services->[$i]->{'serviceType'};
    while (my ($pattern,$sn) = each %$short_svc_names) {
	if ($services->[$i]->{'serviceType'} =~ /$pattern/) {
		$services->[$i]->{'shortname'} = $sn;
	}
    }

    print "\n";
    $i++;
}


print "Processing each service\n";
for my $service (@$services) {
	my $full_url = $server_root_url.$service->{'SCPDURL'};
	print "Service: ", $service->{'serviceId'}, "\n";
	print "--> Downloading SCPD URL: ", $full_url, "\n";
	my $code = system "curl -sO $full_url";
	if ($code != 0) {
		print "--> Download failed, but continuing in case it was already downloaded\n";
	} else {
		print "--> Download complete\n";
	}

	my $scpdfile = basename $full_url;
	if (! -e $scpdfile) {
		# fail if the file cannot be found
		die "--> SCPD file $scpdfile is missing\n";
	}
	$service->{'scpdfile'} = $scpdfile;
	print "--> SCPD filename: $scpdfile\n";
	print "--> Generating seeds...\n";
	&generate_seeds($numseeds,$service);
	print "--> Seed generation completed for service $service->{'serviceId'}\n\n";
}

# get all the possible state variables used by a service, their data type
# and their allowed values if applicable
sub get_state_variables_and_allowed_values {
	my $parser = shift;
	my $shash = shift;

	my $sv = {};
	my $allowedvalues = {};
	my $allowedranges = {};

	# find all state variables
	my $statevars = $parser->find('/scpd/serviceStateTable/stateVariable');
	for my $sv_node ($statevars->get_nodelist) {
	    my $sv_name = $parser->find('./name', $sv_node)->to_literal();
	    my $sv_datatype = $parser->find('./dataType', $sv_node)->to_literal();
	    $sv->{$sv_name} = $sv_datatype;
	    $allowedvalues->{$sv_name} = [];
	    $allowedranges->{$sv_name} = [];
	    if ($sv_datatype eq 'string') {
		my $sv_allowedvalues = $parser->find('./allowedValueList/allowedValue', $sv_node);
		for my $av ($sv_allowedvalues->get_nodelist) {
			push @{$allowedvalues->{$sv_name}}, $av->string_value;
		}
	    } else {
		my $sv_allowedrange_min = $parser->find('./allowedValueRange/minimum', $sv_node);
		for my $av ($sv_allowedrange_min->get_nodelist) {
			push @{$allowedranges->{$sv_name}}, $av->string_value;
		}
		my $sv_allowedrange_max = $parser->find('./allowedValueRange/maximum', $sv_node);
		for my $av ($sv_allowedrange_max->get_nodelist) {
			push @{$allowedranges->{$sv_name}}, $av->string_value;
		}
	    }
	}

	if ($debug) {
	   for my $k (keys %$sv) {
		print "state variable: $k, type: $sv->{$k}\n";
		if ($allowedvalues->{$k} && @{$allowedvalues->{$k}} > 0) {
			print "  allowed values: @{$allowedvalues->{$k}}\n";
		}
		if ($allowedranges->{$k} && @{$allowedranges->{$k}} > 0) {
			print "  allowed value range: @{$allowedranges->{$k}}\n";
		}
	   }
	}

	# save newly parsed data in service hash
	$shash->{'statevars'} = $sv;
	$shash->{'allowedvalues'} = $allowedvalues;
	$shash->{'allowedranges'} = $allowedranges;
}

# get all the actions and arguments supported by the service
sub get_actions_and_arguments {
	my $parser = shift;
	my $shash = shift;

	# get all the supported actions
	my $actions = $parser->find('/scpd/actionList/action');
	my $args = {};

	my $i = 0;
	for my $action_node ($actions->get_nodelist) {
	    my $action_name = $parser->find('./name', $action_node)->to_literal();
	    $args->{$action_name} = [];
	    # get all the arguments for the current action
	    my $arguments = $parser->find('./argumentList/argument', $action_node);
	    my $j = 0;
	    for my $arg_node ($arguments->get_nodelist) {
	    	# get argument properties
		my $name = $parser->find('./name', $arg_node)->to_literal();
		my $dir  = $parser->find('./direction', $arg_node)->to_literal();
		my $rsv  = $parser->find('./relatedStateVariable', $arg_node)->to_literal();
		my $h = {'name' => $name, 'dir' => $dir, 'rsv' =>$rsv};
		$args->{$action_name}->[$j] = $h;
		$j++;
	    }
	    $i++;
	}

	if ($debug) {
	   for my $k (keys %$args) {
		print "action: $k\n";
		print "  arguments:\n";
		map { print "   - ", $_->{'name'}, "\n",
	          "     allowed values: ",
		  "@{$shash->{'allowedvalues'}->{$_->{'rsv'}}}", "\n",
	          "     allowed range: ",
		  "@{$shash->{'allowedranges'}->{$_->{'rsv'}}}", "\n"
		} @{$args->{$k}};
	   }
	}

	# save newly parsed data in service hash
	$shash->{'arguments'} = $args;
}


# generates possible seeds based on a SCPD description
sub generate_seeds {
	my $nseeds_per_action = shift;
	my $shash = shift;

	my $service_type = $shash->{'serviceType'};
	my $shortservicename = $shash->{'shortname'};
	my $scpd_filename = $shash->{'scpdfile'};

	if ($nseeds_per_action <= 0) {
		die "Wrong argument type for nseeds\n";
	}
	
	# start XML parser for the service description
	my $xpscpd = XML::XPath->new(filename => $scpd_filename);
	
	print "Getting all state variables and allowed values\n";
       	&get_state_variables_and_allowed_values($xpscpd,$shash);

	print "Getting all actions and arguments\n";
       	&get_actions_and_arguments($xpscpd,$shash);
	
	my $serializer = SOAP::Serializer->new();
	# uncomment following line to serialize in a more readable way
	# $serializer->readable('true');
	$serializer->envprefix('s');
	
	# workaround to display the envelope attributes that we want, see
	# http://plosquare.blogspot.com/2012/03/adding-attributes-to-soap-lite-envelope.html
	my $envelope_orig = \&SOAP::Serializer::envelope;
	*SOAP::Serializer::envelope = sub {
	    my $str = $envelope_orig->(@_);
	    $str =~ s{xmlns:xsi=[^<>]+}{}s;
	    $str =~ s{xmlns:xsd=[^<>]+}{}s;
	    return $str;
	};

	my $args = $shash->{'arguments'};
	my $sv = $shash->{'statevars'};
	my $allowedvalues = $shash->{'allowedvalues'};
	my $allowedranges = $shash->{'allowedranges'};

	for my $k (sort keys %$args) {
	   print "action: $k\n";
	   # construct an array of arrays of allowed values for each argument
	   my @argallowed = ();
	   for my $a (@{$args->{$k}}) {
		my $dtype = $sv->{$a->{'rsv'}};
	   	print "arg: $a->{'name'}, dtype: $dtype\n";
		my $aval  = $allowedvalues->{$a->{'rsv'}};
		# consider only the allowed values of writable arguments
		# (with direction = in)
		if ($dtype ne 'string' || $a->{'dir'} ne 'in' || @$aval == 0) {
			$aval = ['__undef__'];
		}
		push (@argallowed, $aval);
	   }
	   # count combinations of allowed writable values
	   my $argcount = @{$args->{$k}};
	   print "counting arg combinations ($argcount args)\n";
	   my $ncombinations = 0;
	   my $it = NestedLoops(\@argallowed);
	   while (my @current_allowed_values = $it->()) {
	   	  print join ",", @current_allowed_values; print "\n";
		  $ncombinations++;
	   }
	   if ($ncombinations == 0) {$ncombinations = 1;}
	   print "number of argument combinations for action $k: ",
	  	 $ncombinations, "\n";

	   # when counter is 0, generate just a seed with all empty arguments
	   # after that continue until the number of seeds requested or
	   # until there are no more combinations of arguments
	   for my $counter (0 .. min($nseeds_per_action - 1, $ncombinations)) {
		# seed file name to write
		my $formattednum = sprintf("%02d", $seedcounter);
		my $fname = $formattednum."_".$shortservicename."-".$k."_".$counter;
		$seedcounter++;
		print "generating seed: $fname";
		my $method_args = [];
		my $aindex = 0;
	   	my @current_allowed_values = ();
		if ($counter > 0) {
	   	   @current_allowed_values = $it->();
	        } else {
		   print "  (with empty arguments)";
	        }
	   	print "\n";
	   	print "current allowed val: ",
			(@current_allowed_values == 0) ?
			"(none)" : join ",", @current_allowed_values;
		print "\n";
		for my $a (@{$args->{$k}}) {
			if ($debug) {
				print "   -> name: ", $a->{'name'}, "\n";
				print "   -> dir: ", $a->{'dir'}, "\n";
				print "   -> rsv: ", $a->{'rsv'}, "\n";
			}
			my $dtype  = $sv->{$a->{'rsv'}};
			my $aval   = $allowedvalues->{$a->{'rsv'}};
			my $arange = $allowedranges->{$a->{'rsv'}};

			# first generate seed with empty values for arguments
			my $allowedv = '';
			my $argval = '';
			# only pass arguments inbound to the action!
			if ($a->{'dir'} eq 'in') {
				# then generate argument values
				if ($counter > 0) {
					$allowedv = $current_allowed_values[$aindex];
					$argval = &gen_args($dtype, $allowedv, $arange);
					print "      ---> generated argument value: ", $argval, "\n" if ($debug);
				}
				push @{$method_args}, SOAP::Data->new(
					name => $a->{'name'},
					value => $argval)->attr({'xmlns'=>undef, 'xsi:type'=>undef});
			}
			$aindex++;
		} # for args

		# serialize XML into the seed file
		my $elem;
		open my $fh, '>', $fname;
		if (@$method_args > 0) {
			$elem = SOAP::Data->name('u:'.$k => \SOAP::Data->name("arrayitem" => @{$method_args}));
			$elem->attr({'xmlns:soap'=>undef,
				    'xmlns:soapenc'=>undef,
				    'xsi:nil'=>undef,
				    'xmlns:xsd'=>undef,
				    'xmlns'=>undef,
				    'xmlns:u'=>$service_type,
				    'xmlns:xsi'=>undef});
			print $serializer->envelope(freeform=>($elem)), "\n";
			print $fh $serializer->envelope(freeform=>($elem)), "\n";
		} else {
			$elem = SOAP::Data->name('u:'.$k);
			$elem->attr({'xmlns:soap'=>undef,
				    'xmlns:soapenc'=>undef,
				    'xsi:nil'=>undef,
				    'xmlns:xsd'=>undef,
				    'xmlns'=>undef,
				    'xmlns:u'=>$service_type,
				    'xmlns:xsi'=>undef});
			print $serializer->envelope(freeform=>($elem)), "\n";
			print $fh $serializer->envelope(freeform=>($elem)), "\n";
			# no need to generate the same message twice
			# if there are no arguments that can vary
			last;
		}
		close $fh;
		print "\n";
	   } # for seeds per action
	} # for actions
}

sub gen_args {
	my $type = shift;
	my $value_to_use = shift;
	my $allowedrange = shift;
	print "generating value of type $type\n" if $debug;

	my @valid_datatypes = qw/ui1 ui2 ui4 i1 i2 i4 int r4 r8 number float
	  char string date dateTime time boolean bin.base64 bin.hex uri uuid/;
	my $invalid = 1;
	for my $vdt (@valid_datatypes) {
		$invalid = 0 if ($vdt eq $type);
	}
	if ($invalid) {
		die "invalid datatype $type\n";
	}

	# generate number (within range if specified)
	my ($minval, $maxval);
	my $applylimits = 0;
        if (@$allowedrange == 2) {
		($minval, $maxval) = @$allowedrange;
		$applylimits = 1;
	}
	my $retval = 1e9999;
	if ($type eq 'ui1') {
		$retval = zgmp_urandomb_ui($state, 8);
		$retval = zgmp_urandomb_ui($state, 8)
			while ($applylimits && ($retval < $minval || $retval > $maxval));
	} elsif ($type eq 'ui2') {
		$retval = zgmp_urandomb_ui($state, 16);
		$retval = zgmp_urandomb_ui($state, 16)
			while ($applylimits && ($retval < $minval || $retval > $maxval));
	} elsif ($type eq 'ui4') {
		$retval = zgmp_urandomb_ui($state, 32);
		$retval = zgmp_urandomb_ui($state, 32)
			while ($applylimits && ($retval < $minval || $retval > $maxval));
	} elsif ($type eq 'i1') {
		$retval = zgmp_urandomb_ui($state, 8);
		$retval = zgmp_urandomb_ui($state, 8)
			while ($applylimits && ($retval < $minval || $retval > $maxval));
	} elsif ($type eq 'i2') {
		$retval = zgmp_urandomb_ui($state, 16);
		$retval = zgmp_urandomb_ui($state, 16)
			while ($applylimits && ($retval < $minval || $retval > $maxval));
	} elsif ($type eq 'i4') {
		$retval = zgmp_urandomb_ui($state, 32);
		$retval = zgmp_urandomb_ui($state, 32)
			while ($applylimits && ($retval < $minval || $retval > $maxval));
	} elsif ($type eq 'int') {
		$retval = zgmp_urandomb_ui($state, 64);
		$retval = zgmp_urandomb_ui($state, 64)
			while ($applylimits && ($retval < $minval || $retval > $maxval));
	} elsif ($type eq 'boolean') {
		$retval = zgmp_urandomb_ui($state, 1);
	} elsif ($type eq 'char') {
		$retval = chr zgmp_urandomb_ui($state, 7);
	} elsif ($type eq 'string') {
		if ($value_to_use && $value_to_use ne '__undef__') {
			print "  (not random but value selected from a list of allowed values)\n" if $debug;
			$retval = $value_to_use;
		} else {
			# avoid < and > tokens for xml, and use ASCII
			# characters with a normal display
			# make the random strings 16 characters long
			my @num_array = (1 .. 16);
			my @rand_string =
		           map {
			       	my $a = '<';
			       	until ($a ne '<' && $a ne '>'
			         	&& $a ne '&' && $a ne ' ') {
					       	$a = chr (32 + int rand 94);
				       	} ;
				       	$_ = $a;
			       } @num_array;
			$retval = join "", @rand_string;
		}
	} elsif ($type eq 'bin.base64') {
		# generate any sequence of 16 bytes and then encode to base64
		my @num_array = (1 .. 16);
		my @rand_sequence = map { $_ = zgmp_urandomb_ui($state, 8); } @num_array;
		$retval = encode_base64((join '', @rand_sequence), '');
	} else { 
		$retval = "gen_args: not yet implemented";
	}
	return $retval;
}

