#
#
# This script is (C) Tenable Network Security
#
#

if (description)
{
 script_id(19376);
 script_version ("$Revision: 1.3 $");
 script_name(english:"ARCServe MSSQL Agent detection");
 desc["english"] = "
Synopsis :

A backup software is listening on this port.

Description :

The BrightStor ARCServe MSSQL Agent is installed on the remote
host.

Solution :

If this service is not needed, disable it or filter incoming traffic
to this port.

Risk factor : 

None";
 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is running BrightStor ARCServe MSSQL Agent");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_require_ports (6070);
 exit(0);
}

port = 6070;
soc = open_sock_tcp (port);
if (!soc) exit(0);

data = "[LUHISL" + crap(data:"A", length:700);

send (socket:soc, data:data);
ret = recv (socket:soc, length:4096);

if ((strlen(ret) == 8) && ( "0000041b00000000" >< hexstr(ret) ))
{
 security_note (port);
 set_kb_item (name:"ARCSERVE/MSSQLAgent", value:TRUE);
}
