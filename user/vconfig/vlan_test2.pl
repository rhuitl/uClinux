#!/usr/bin/perl

# Arguments:
#  clean  Remove interfaces.

use strict;

$| = 1;

my $num_if = 4000;

`modprobe 8021q`;
print "Memory after loading 8021q module: ";
print `free`;
print "\n";

`/usr/local/bin/vconfig set_name_type VLAN_PLUS_VID_NO_PAD`;

my $d = 5;
my $c = 5;

if ($ARGV[0] ne "clean") {

  my $i;
  print "Adding VLAN interfaces 1 through $num_if\n";

  print "Turnning off /sbin/hotplug...\n";
  `echo  > /proc/sys/kernel/hotplug`;

  my $p = time();
  for ($i = 1; $i<=$num_if; $i++) {
    `/usr/local/bin/vconfig add eth0 $i`;
    #`ip address flush dev vlan$i`;
    `ip address add 192.168.$c.$c/24 dev vlan$i`;
    `ip link set dev vlan$i up`;

    $d++;
    if ($d > 250) {
      print ".";
      $d = 5;
      $c++;
    }
  }

  print "\nMemory after creating $i vlan devices: ";
  print `free`;
  print "\n";

  print "Doing ifconfig -a for $i devices.\n";
  `time -p ifconfig -a > /tmp/vlan_test_ifconfig_a_$i.txt`;
  print "Doing ip addr show for $i devices.\n";
  `time -p ip addr show > /tmp/vlan_test_ip_addr_$i.txt`;

  my $n = time();
  my $diff = $n - $p;

  print "Done adding $num_if VLAN interfaces in $diff seconds.\n";

  sleep 2;
}

print "Removing VLAN interfaces 1 through $num_if\n";
$d = 5;
$c = 5;
my $p = time();
my $i;
for ($i = 1; $i<=$num_if; $i++) {
  `/usr/local/bin/vconfig rem vlan$i`;
}
my $n = time();
my $diff = $n - $p;
print "Done deleting $num_if VLAN interfaces in $diff seconds.\n";

print "Memory after deleting $i vlan devices: ";
print `free`;
print "\n";

sleep 2;


if ($ARGV[0] ne "clean") {

  my $tmp = $num_if * 4;
  print "\nGoing to add and remove 2 interfaces $tmp times.\n";
  $p = time();
  
  
  for ($i = 1; $i<=$tmp; $i++) {
    `/usr/local/bin/vconfig add eth0 1`;
    `ifconfig vlan1 192.168.200.200`;
    `ifconfig vlan1 up`;
    `ifconfig vlan1 down`;
    
    `/usr/local/bin/vconfig add eth0 2`;
    `ifconfig vlan2 192.168.202.202`;
    `ifconfig vlan2 up`;
    `ifconfig vlan2 down`;
    
    `/usr/local/bin/vconfig rem vlan2`;
    `/usr/local/bin/vconfig rem vlan1`;

    if (($i % 125) == 0) {
      print ".";
    }
  }
  $n = time();
  $diff = $n - $p;
  print "\nDone adding/removing 2 VLAN interfaces $tmp times in $diff seconds.\n";
}

print "Re-installing /sbin/hotplug...\n";
`echo /sbin/hotplug > /proc/sys/kernel/hotplug`;

print "Memory at end of the run: ";
print `free`;
print "\n";
