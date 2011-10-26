#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10045);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-1999-0889");
 name["english"] = "Cisco 675 passwordless router";
 name["francais"] = "Cisco 675 sans mot de passe";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote CISCO router is passwordless. This means
that anyone can telnet to it and reconfigure it to lock
you out of it, and to prevent you to use your internet
connection.

Solution : telnet to this router and set a password
immediately.

Risk factor : High";


 desc["francais"] = "
Le routeur CISCO distant n'a pas de mot de passe. Cela
signifie que n'importe qui peut y faire un telnet
et le reconfigurer pour vous empecher d'y acceder
par la suite, et vous empecher d'avoir accès
à internet.

Solution : faites immédiatement un telnet sur ce
routeur et mettez un mot de passe.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Logs into the remote CISCO router";
 summary["francais"] = "Se loggue dans le routeur CISCO distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Misc.";
 family["francais"] = "Misc.";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(23);
 
 exit(0);
}

#
# The script code starts here
#
include('telnet_func.inc');

port = 23;
if(get_port_state(port))
{
 buf = get_telnet_banner(port:port);
 if ( ! buf || "User Access Verification" >!< buf ) exit(0);
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = telnet_negotiate(socket:soc);
  if("User Access Verification" >< buf)
  {
   buf = recv(socket:soc, length:1024);
   data = string("\r\n");
   send(socket:soc, data:data);
   buf2 = recv(socket:soc, length:1024);
   if(">" >< buf2)security_hole(port);
  }
 close(soc);
 }
}
