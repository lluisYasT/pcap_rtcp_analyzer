#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use autodie;
use Net::IP;

sub help {
  print "usage: $0 <pcap_file> <src_ip_address>\n"
}

sub analyze_call {
  my @packets = @_;
  my %call_info;
  $call_info{time} = $packets[0]{time};
  my $index = 0;
  ($call_info{loss}, $call_info{jitter}) = (0, 0);
  while ($index < $#packets) {
    $call_info{loss} += $packets[$index]{fraction_lost} if $packets[$index]{fraction_lost};
    $call_info{jitter} += $packets[$index]{jitter} if $packets[$index]{jitter};
    $index++;
  }
  $call_info{loss} /= $index;
  $call_info{jitter} /= $index;
  print "Date: $call_info{time}\n";
  printf "\tPacket loss: %.2f\n", $call_info{loss};
  printf "\tJitter: %.2fms\n\n", $call_info{jitter} / 8;
  
  return %call_info;
}

if ($#ARGV < 0 or $#ARGV > 2) { 
  help;
  exit 0;
}

my $pcap_filename = shift;
my $src_ip = new Net::IP(shift) or die (Net::IP::Error());

open(my $fh, '-|', "tshark -V -r $pcap_filename -t ad -R 'ip.src==" . $src_ip->ip . " and rtcp' -2") or die "Error executing tshark";

my %call_info;
my $same_call = 0;


my @decoded_packets;
my %packet_info;
my $index = 0;

while (<$fh>) {
  if(/^\s+?Arrival Time: (.*)$/) {
    $decoded_packets[$index]{time} = $1;
    next;
  }

  if (/Packet type: Goodbye/) {
    analyze_call(@decoded_packets) if ($index > 0);
    @decoded_packets = ();
    $index = -1;
    next;
  }
  if (/^$/) {
    $index++;
    next;
  }

  if(/^\s+?Fraction lost: (\d+) \/ 256$/) {
    $decoded_packets[$index]{fraction_lost} = $1;
    next;
  }
  if(/^\s+?Interarrival jitter: (\d+)$/) {
    $decoded_packets[$index]{jitter} = $1;
  }

}

close($fh);
