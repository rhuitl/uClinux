# This plugin was written by Michel Arboi <arboi@alussinan.org>
# It is released under the GNU Public Licence (GPLv2)
#
# See RFC 827 & RFC 888
#

if(description)
{
  script_id(11908);
  script_version ("$Revision: 1.8 $");

  name["english"] = "EGP detection";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote IP stack answers to an obsolete protocol.

Description :

The remote host is running EGP, an obsolete routing protocol.

If possible, this IP protocol should be disabled.

Solution :

If this protocol is not needed, disable it or filter incoming traffic going
to IP protocol #8

Risk factor : 

None";

  script_description(english:desc["english"]);
 
  summary["english"] = "Sends an EGP Neighbor Acquisition Message";
  script_summary(english:summary["english"]);
  script_category(ACT_GATHER_INFO); 
  script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
  script_family(english:"Service detection");
  exit(0);
}


##include("dump.inc");
include('global_settings.inc');
include("network_func.inc");
if (islocalhost() || ! thorough_checks) exit(0);

s = this_host();
v = eregmatch(pattern: "^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9])+$", string: s);
if (isnull(v)) exit(0);
for (i = 1; i <=4; i++) a[i] = int(v[i]);

a1 = rand() % 256; a2 = rand() % 256;
s1 = rand() % 256; s2 = rand() % 256;

r = raw_string(	2,	# EGP version
		3,	# Type
		0,	# Code = Neighbor Acquisition Request
		0,	# Info (not used here)
		0, 0,	# checksum
		a1, a2,	# Autonomous system
		s1, s2,	# Identification
		0, 30,	# NR Hello Interval
		0, 120	# NR Poll Interval
	);

ck = ip_checksum(data: r);
r2 = insstr(r, ck, 4, 5);

egp = forge_ip_packet(ip_v: 4, ip_hl: 5, ip_tos: 0, ip_p: 8, ip_ttl: 64,
			ip_off: 0, ip_src: this_host(),	data: r2);

f = "ip proto 8 and src " + get_host_ip();
for ( i = 0 ; i < 3 ; i ++ )
{
 r = send_packet(egp, pcap_active: TRUE, pcap_filter: f, pcap_timeout:1);
 if ( r ) break;
}
if ( r == NULL ) exit(0);

hl = ord(r[0]) & 0xF; hl *= 4;
egp = substr(r, hl);
if (ord(egp[0]) == 2 && ord(egp[1]) == 3 && ord(egp[2]) <= 4)
  security_warning(port: 0, proto: "egp");
