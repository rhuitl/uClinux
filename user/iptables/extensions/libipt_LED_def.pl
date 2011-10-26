# Generate keyword tables from ledman.h.

my @cmds;
my @leds;

while (<>) {
    if (/^#define\s+LEDMAN_CMD_([A-Z0-9_]+)/) {
	push @cmds, $1;
    } elsif (@cmds || /LEDMAN_MAX/) {
	next;
    } elsif (/^#define\s+LEDMAN_([A-Z0-9_]+)/) {
	push @leds, $1;
    }
}

print "  { \"$_\", LEDMAN_$_ },\n"
    foreach (@leds);
