#!/usr/bin/perl

srand();

@salts = (".", "/", "0".."9", "A".."Z", "a".."z");
$salt = $salts[int(rand(64))] . $salts[int(rand(64))];

my $passwd = shift;
my $encrypted = crypt($passwd, $salt);

print "${encrypted}";
