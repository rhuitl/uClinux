#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10790);
script_cve_id("CVE-2001-0838");
 script_version ("$Revision: 1.8 $");
 
 name["english"] = "rwhois format string attack";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote rwhois daemon is vulnerable to a format string
attack when supplied malformed arguments to a '-soa' request.

An attacker may use this flaw to gain a shell on this host.

Risk factor : High
Solution : Disable this service or upgrade to a patched version";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if rwhois is vulnerable to a format string attack";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/rwhois", 4321);
 exit(0);
}

#
# The script code starts here
#

port = 4321;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  r = recv(socket:soc, length:4096);
  send(socket:soc, data:string("-soa %p\r\n"));
  r = recv(socket:soc, length:4096);
  close(soc);
  if(egrep(pattern:"^%error 340 Invalid Authority Area: 0x.*", 
	  string:r))security_hole(4321);
 }
}
