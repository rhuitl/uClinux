#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# We don't actually check for the flaw.
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11312);
 script_bugtraq_id(4701, 6627, 6628, 11591);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2002-0702", "CVE-2003-0026", "CVE-2003-0039", "CVE-2004-1006");
 if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2003:034-01");
 
 name["english"] = "DHCP server overflow / format string bug";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a DHCP server.

If the remote server is ISC-DHCPd, make sure you are running
the latest version, as several flaws affect older versions and
may allow an attacker to gain root on this host

*** Note that Nessus did not check for the presence of the
*** flaws, so this might be a false positive


See also : http://www.cert.org/advisories/CA-2003-01.html
           http://www.cert.org/advisories/CA-2002-12.html
	   
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Chats with the remote DHCP server";
 summary["francais"] = "Discute avec le serveur DHCP distant";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("os_fingerprint.nasl", "dhcp.nasl");
 script_require_keys("DHCP/Running");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


os = get_kb_item("Host/OS/icmp");
if(os)
{
 # Windows is not affected
 if(egrep(pattern:"windows", string:os, icase:TRUE))exit(0);
 
 # OpenBSD not affected
 if(egrep(pattern:"openbsd", string:os, icase:TRUE))exit(0);
 
 # CISCO not affected
 if(egrep(pattern:"cisco", string:os, icase:TRUE))exit(0);
 
 # Hitachi not affected
 if(egrep(pattern:"hitachi", string:os, icase:TRUE))exit(0);
 
 # NetBSD >= 1.5 not affected
 if(egrep(pattern:"NetBSD 1\.[5-9]\..*", string:os, icase:TRUE))exit(0);
 
 # MacOS X not affected
 if(egrep(pattern:"Mac OS 10", string:os))exit(0);
 
 # FreeBSD not affected
 if(egrep(pattern:"FreeBSD", string:os))exit(0);
} else exit(0);

# Can't test on localhost due to libpcap on linux :(
if(islocalhost())exit(0);



#----------------------------------------------------------#
# Forgery                                                  #
#----------------------------------------------------------#


# Options we are interested in seeing.

opts = raw_string(1, 3, 4, 5, 6, 7, 8, 9, 
		  10, 11, 12, 14, 15, 16, 
		  17, 19, 20, 28, 40, 41, 
		  42, 44, 45, 48, 49, 54, 
		  64, 65, 66, 67, 68, 69, 
		  70, 71, 72, 73, 74, 75, 76);


len = strlen(opts);



#
# Note that we lie to the remote DHCP server by telling
# it our ether address is FF:FF:FF:FF:FF. We do that 
# so that we can get a reply from the server (nasl
# does not know how to extract one's MAC address yet)
#
#

# (we choose a random request id)
a = rand() % 255;
b = rand() % 255;
c = rand() % 255;
d = rand() % 255;


req = raw_string(
	0x01, 0x01, 0x06, 0x00, a,    b,    c,    d,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82,
	0x53, 0x63, 0x35, 0x01, 0x01, 0x37, len) + opts +
	raw_string( 
	0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00);
	
len = strlen(req);
addr = this_host();
ip = forge_ip_packet(
		ip_v    : 4,
		ip_hl   : 5,
		ip_len  : 20 + 8 + len,
		ip_id   : 0x1234,
		ip_p    : IPPROTO_UDP,
		ip_tos  : 0,
		ip_ttl  : 0x40,
		ip_off  : 0,
		ip_src  : addr);
		
udp = forge_udp_packet(
		ip	: ip,
		uh_sport: 68,
		uh_dport: 67,
		uh_ulen : 8 + len,
		data    : req);
		

#
# Removing the 'src host' part of the pcap filter may be wise, 
# as some DHCP server  will ask another agent to reply for them. But 
# if we do that, we may encounter some problems when the same plugin is 
# started against two hosts at the same time, and in addition to
# this, we want to test this remote server, not another one.
#		
filter = string("udp and src host ", get_host_ip(), " and src port ", 67,
		" and dst port ", 68);
		
rep = send_packet(udp, pcap_active:TRUE, pcap_filter:filter);		
if(rep)
{
 data = get_udp_element(element:"data", udp:rep);
 if(strlen(data) < 14)exit(0);
 security_hole(port:67, proto:"udp");
}

