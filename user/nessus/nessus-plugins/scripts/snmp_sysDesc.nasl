#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

The System Information of the remote host can be obtained via SNMP.

Description :

It is possible to obtain the system information about the remote
host by sending SNMP requests with the OID 1.3.6.1.2.1.1.1.

An attacker may use this information to gain more knowledge about
the target host.

Solution : 

Disable the SNMP service on the remote host if you do not use it,
or filter incoming UDP packets going to this port.

Risk factor : 

Low";


if(description)
{
 script_id(10800);
 script_version ("$Revision: 1.14 $");
 
 name["english"] = "Obtain system info type via SNMP";
 
 script_name(english:name["english"]);

 script_description(english:desc["english"]);
 
 summary["english"] = "Enumerates system info via SNMP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SNMP";
 script_family(english:family["english"]);
 
 script_dependencie("snmp_settings.nasl");
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


system = NULL;

descr = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.1.1.0");
objectid = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.1.2.0");
uptime = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.1.3.0");
contact = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.1.4.0");
name = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.1.5.0");
location = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.1.6.0");
services = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.1.7.0");

if (descr || objectid || uptime || contact || name || location || services)
  system =
string (
"System information :\n",
" sysDescr     : ", descr, "\n",
" sysObjectID  : ", objectid, "\n",
" sysUptime    : ", uptime, "\n",
" sysContact   : ", contact, "\n",
" sysName      : ", name, "\n",
" sysLocation  : ", location, "\n",
" sysServices  : ", services, "\n",
"\n"
);

if(strlen(system))
{
 if (descr)
   set_kb_item(name:"SNMP/sysDesc", value:descr);
 if (objectid)
   set_kb_item(name:"SNMP/OID", value:objectid);


 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		system);

 security_note(port:port, data:report, protocol:"udp");
}
