#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10754);
 script_cve_id("CVE-1999-0508");
 script_version ("$Revision: 1.10 $");
 
 
 name["english"] = "Cisco password not set";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote CISCO router has no password set.
This allows an attacker to get a lot information
about your network, and possibly to shut it down if
the 'enable' password is not set either.

Solution : telnet to this device and set a password
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the absence of a password";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");

 family["english"] = "CISCO";
 family["francais"] = "CISCO";

 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/telnet", 23);
 exit(0);
}


include('telnet_func.inc');

function test_cisco(password, port)
{
 soc = open_sock_tcp(port);

 if(soc)
 {
  r = telnet_negotiate(socket:soc);
  r = recv(socket:soc, length:4096);
  send(socket:soc, data:string(password, "\r\n"));
  r = recv(socket:soc, length:4096);
  send(socket:soc, data:string("show ver\r\n"));
  r = recv(socket:soc, length:4096);
  if("Cisco Internetwork Operating System Software" >< r)security_hole(port);
  close(soc);
 }
}


port = get_kb_item("Services/telnet");
if(!port)port = 23;
if(!get_port_state(port))exit(0);

banner = get_telnet_banner(port:port);
if ( ! banner || "User Access Verification" >!< banner ) exit(0);


test_cisco(password:"", port:port);
