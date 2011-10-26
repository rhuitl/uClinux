#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11974);
 script_bugtraq_id(9316);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "Jordan Windows Telnet Server Overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Jordan Windows Telnet Server.

There is a buffer overflow in this server which may allow anyone to
execute arbitrary commands on this host by supplying a too long password.

Solution : Disable this service
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of the remote telnet server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2004 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/telnet", 23);
 exit(0);
}


include('telnet_func.inc');
port = get_kb_item("Services/telnet");
if(!port)port = 23;
r = get_telnet_banner(port:port);
if(!r)exit(0);
if ( "Windows Telnet Server Version 1." >< r ) security_hole(port);
