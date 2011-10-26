#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

The list of LANMAN users of the remote host can be obtained via SNMP.

Description :

It is possible to obtain the list of lanman users on the remote
host by sending SNMP requests with the OID 1.3.6.1.4.1.77.1.2.25.1.1

An attacker may use this information to gain more knowledge about
the target host.

Solution : 

Disable the SNMP service on the remote host if you do not use it,
or filter incoming UDP packets going to this port.

Risk factor : 

Low";

if(description)
{
 script_id(10546);
 script_version ("$Revision: 1.24 $");
 
 name["english"] = "Enumerate Lanman users via SNMP";
 
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Enumerates users via SNMP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SNMP";
 script_family(english:family["english"]);
 
 script_dependencies("snmp_settings.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}

include ("snmp_func.inc");


community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port)port = 161;

soc = open_sock_udp(port);
if (!soc)
  exit (0);

users = scan_snmp_string (socket:soc, community:community, oid:"1.3.6.1.4.1.77.1.2.25.1.1");

if(strlen(users))
{
 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		users);

 security_note(port:port, data:report, protocol:"udp");
}
