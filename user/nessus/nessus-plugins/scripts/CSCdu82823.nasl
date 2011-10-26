#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#
# Thanks to Nicolas FISCHBACH (nico@securite.org) for his help
#
# Ref:  http://www.cisco.com/warp/public/707/vpn3k-multiple-vuln-pub.shtml


if(description)
{
 script_id(11290);
 script_version("$Revision: 1.3 $");
 script_cve_id("CVE-2001-0427");

 name["english"] = "CSCdu82823";

 script_name(english:name["english"]);

 desc["english"] = "
The remote VPN concentrator has a bug in its
implemenation of telnetd.

This vulnerability is documented as Cisco bug ID CSCdu82823.

Solution : 
http://www.cisco.com/warp/public/707/vpn3k-multiple-vuln-pub.shtml
Risk factor : High

*** As Nessus solely relied on the banner of the remote host
*** this might be a false positive
";
 script_description(english:desc["english"]);

 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2003 Renaud Deraison");

 script_family(english:"CISCO");

 script_require_ports(23);
 script_dependencie("snmp_sysDesc.nasl");
 script_require_keys("SNMP/community",
			  "SNMP/sysDesc",
			  "CISCO/model");
 exit(0);
}


if(!get_port_state(23))exit(0);
soc = open_sock_tcp(23);
if(!soc)exit(0);
else close(soc);


# The code starts here
ok=0;

os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);



# Is this a VPN3k concentrator ?
if(!egrep(pattern:".*VPN 3000 Concentrator.*", string:os))exit(0);


# < 3.0.4
if(egrep(pattern:".*Version 3\.0\.Rel.*", string:os))ok = 1;
if(egrep(pattern:".*Version 3\.0\.[0-3].*", string:os))ok = 1;

# 2.x.x
if(egrep(pattern:".*Version 2\..*", string:os))ok = 1;


if(ok)security_hole(port:161, proto:"udp");
