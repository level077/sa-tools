#!/usr/bin/perl

use Data::Dumper;

sub parse_numa_maps_line($$)
{
  my ($line, $map) = @_;

  if($line =~ /^[> ]*([0-9a-fA-F]+) (\S+)(.*)/)
  {
    my ($address, $policy, $flags) = ($1, $2, $3);

    $map->{$address}->{'policy'} = $policy;

    $flags =~ s/^\s+//g;
    $flags =~ s/\s+$//g;
    foreach my $flag (split / /, $flags)
    {
      my ($key, $value) = split /=/, $flag;
      $map->{$address}->{'flags'}->{$key} = $value;
    }
  }

}

sub parse_numa_maps()
{
  my ($fd) = @_;
  my $map = {};

  while(my $line = <$fd>)
  {
    &parse_numa_maps_line($line, $map);

  }
  return $map;
}

my $map = &parse_numa_maps(\*STDIN);

my $sums = {};

foreach my $address (keys %{$map})
{
  if(exists($map->{$address}->{'flags'}))
  {
    my $flags = $map->{$address}->{'flags'};
    foreach my $flag (keys %{$flags})
    {
      next if $flag eq 'file';
      $sums->{$flag} += $flags->{$flag} if defined $flags->{$flag};
    }
  }
}

foreach my $key (sort keys %{$sums})
{
  printf "%-10s: %12i (%6.2f GB)\n", $key, $sums->{$key}, $sums->{$key}/262144;
}
