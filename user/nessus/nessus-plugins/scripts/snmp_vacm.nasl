#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

The SNMP private community strings can be retrieved using SNMP.

Description :

It is possible to obtain the remote private community strings using
the View-Based Access Control MIB of the remote Cisco router.

An attacker may use this flaw to gain read/write SNMP access
on this router.

Solution : 

Disable the SNMP service on the remote host if you do not use it,
or filter incoming UDP packets going to this port or install Cisco
patch.

http://www.cisco.com/warp/public/707/ios-snmp-community-vulns-pub.shtml

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


if(description)
{
 script_id(10688);
 script_bugtraq_id(2427);
 script_version ("$Revision: 1.14 $");
 
 name["english"] = "SNMP VACM";
 
 script_name(english:name["english"]);

 script_description(english:desc["english"]);
 
 summary["english"] = "Enumerates communities via SNMP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SNMP";
 script_family(english:family["english"]);
 
 script_dependencies("snmp_settings.nasl","snmp_sysDesc.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}

include ("snmp_func.inc");

oid = get_kb_item("SNMP/OID");
if (!oid)
  exit (0);

# Only checks for cisco, else it could be FP
if (!is_valid_snmp_product(manufacturer:"1.3.6.1.4.1.9.1", oid:oid))
  exit (0);

community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port)port = 161;

soc = open_sock_udp(port);
if (!soc)
  exit (0);

comms = scan_snmp_string (socket:soc, community:community, oid:"1.3.6.1.6.3.16.1.2.1.3");

if(strlen(comms))
{
 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		comms);

 security_hole(port:port, data:report, protocol:"udp");
}
