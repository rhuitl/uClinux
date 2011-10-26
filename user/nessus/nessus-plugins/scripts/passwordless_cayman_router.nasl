#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10345);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-1999-0508");
 

 name["english"] = "Passwordless Cayman DSL router";
 name["francais"] = "Routeur DSL Cayman sans mot de passe";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote router has no password. An intruder
may connect to it and disable them easily.

Solution : Set a password (see http://cayman.com/security.html#passwordprotect)
Risk factor : High";

 desc["francais"] = "
Le routeur distant n'a pas de mot de passe. Un
pirate peut facilement s'y connecter et le désactiver.

Solution : Mettez un mot de passe (cf
http://cayman.com/security.html#passwordprotect)
Facteur de risque : Sérieux";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Notifies that the remote cayman router has no password";
 summary["francais"] = "Signale si le routeur cayman distant n'a pas de mot de passe";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

#
# The script code starts here
#
include('telnet_func.inc');
port = get_kb_item("Services/telnet");
if(!port) port = 23;

if(get_port_state(port))
{
 buf = get_telnet_banner(port:port);
 if ( ! buf || "Terminal shell" >!< buf ) exit(0);
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = telnet_negotiate(socket:soc);
  if("Terminal shell" >< buf)
  	{
	 r = recv(socket:soc, length:2048);
	 b = buf + r;
	 if("completed login" >< b)security_hole(port);
	}
  close(soc);
 }
}
