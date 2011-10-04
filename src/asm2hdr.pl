#!/usr/bin/perl
use strict;
use warnings;
my $usage = "$0 <asm file> <header file> <variable>";
my $obj = $ARGV[0] || die $usage;
my $hdr = $ARGV[1] || die $usage;
my $name = $ARGV[2] || die $usage;
my $ifdef = '__' . uc($name) . '_H__';
my @chars;
do {
	local $/;
	open ASM, "<$obj" or die "Unable to open $obj: $!";
	my $data = <ASM>;
	@chars = map(ord, split('', $data));
};
open HDR, ">$hdr" or die "Unable to open $hdr: $!";
print HDR "#ifndef $ifdef\n#define $ifdef\n";
print HDR 'const unsigned char ' . $name ."[] = {\n";
print HDR "\t", join(', ', @chars), "\n";
print HDR "};\n#endif /* $ifdef */\n";
close HDR;
