#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

The administrative password of the remote HP JetDirect printer can be obtained
using SNMP.


Description :

It is possible to obtain the password of the remote HP JetDirect
web server by sending SNMP requests.

An attacker may use this information to gain administrative access
to the remote printer.

Solution : 

Disable the SNMP service on the remote host if you do not use it,
or filter incoming UDP packets going to this port.

http://www.securityfocus.com/archive/1/313714/2003-03-01/2003-03-07/0

Risk factor : 

High";

if(description)
{
 script_id(11317);
 script_bugtraq_id(5331, 7001);
 script_cve_id("CVE-2002-1048");
 script_version ("$Revision: 1.15 $");
 
 name["english"] = "Discover HP JetDirect EWS Password via SNMP";
 
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Enumerates password of JetDirect Web Server via SNMP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SNMP";
 script_family(english:family["english"]);
 script_dependencie("snmp_sysDesc.nasl");
 exit(0);
}

include ("snmp_func.inc");


oid = get_kb_item("SNMP/OID");
if (!oid)
  exit (0);

# exit if not HP
if (!is_valid_snmp_product(manufacturer:"1.3.6.1.4.1.11", oid:oid))
  exit (0);


community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port)port = 161;

soc = open_sock_udp(port);
if (!soc)
  exit (0);

pass = snmp_request_next (socket:soc, community:community, oid:"1.3.6.1.4.1.11.2.3.9.1.1.13");
if (isnull(pass) || (pass[0] != "1.3.6.1.4.1.11.2.3.9.1.1.13.0"))
  exit (0);

hexpass = hexstr(pass[1]);
if (hexpass == "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") exit(0);

if (strlen(pass[1]) <= 0 && pass[1] =~ "^ *$" )
  password = "Remote printer has no password set";
else
  password = string ("Remote printer password is : ",pass[1]);

report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		password);

security_hole(port:port, data:report, protocol:"udp");
