#
# (C) Tenable Network Security 
#

 desc["english"] = "
Synopsis :

The list of network interfaces cards of the remote host can be obtained via
SNMP.

Description :

It is possible to obtain the list of the network interfaces installed
on the remote host by sending SNMP requests with the OID 1.3.6.1.2.1.2.1.0

An attacker may use this information to gain more knowledge about
the target host.

Solution : 

Disable the SNMP service on the remote host if you do not use it,
or filter incoming UDP packets going to this port.

Risk factor : 

Low";


if(description)
{
 script_id(10551);
 script_version ("$Revision: 1.17 $");
 
 name["english"] = "Obtain network interfaces list via SNMP";
 
 script_name(english:name["english"]);
 script_description(english:desc["english"]);
 
 summary["english"] = "Enumerates processes via SNMP";
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


number = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.2.1.0");
oid = "1.3.6.1.2.1.2.1.0";

network = NULL;

cnt = 0;

for (i=1; i<=number; i++)
{
 index = snmp_request_next (socket:soc, community:community, oid:oid);
 if ( index == NULL ) break;
 descr = snmp_request (socket:soc, community:community, oid:string("1.3.6.1.2.1.2.2.1.2.",index[1]));
 phys = snmp_request (socket:soc, community:community, oid:string("1.3.6.1.2.1.2.2.1.6.",index[1]));

 oid = index[0];

 network += 
 string (
 "Interface ", i, " information :\n",
 " ifIndex       : ", index[1], "\n",
 " ifDescr       : ", descr, "\n",
 " ifPhysAddress : ", hexstr(phys), "\n",
 "\n"
 );

 if (strlen(phys) == 6 )
 {
   str = hexstr(ord(phys[0])) + ':' + hexstr(ord(phys[1])) + ':' + hexstr(ord(phys[2])) + ':' + hexstr(ord(phys[3])) + ':' + hexstr(ord(phys[4])) + ':' + hexstr(ord(phys[5])); 
  set_kb_item(name:"SNMP/ifPhysAddress/" + cnt, value:str);
  cnt++;
 }
}


if(strlen(network))
{
 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		network);

 security_note(port:port, data:report, protocol:"udp");
}
