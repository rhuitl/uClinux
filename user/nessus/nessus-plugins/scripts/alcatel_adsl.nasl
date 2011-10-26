#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
   script_id(10530);
 script_version ("$Revision: 1.8 $");
   name["english"] = "Passwordless Alcatel ADSL Modem";
   name["francais"] = "Modem ADSL Alcatel sans mot de passe";
   script_name(english:name["english"]);
 
   desc["english"] = "
The remote Alcatel ADSL modem has no password set.

An attacker could telnet to this modem and reconfigure it to lock 
you out. This could prevent you from using your Internet 
connection.

Solution : Telnet to this modem and set a password
immediately.

Risk factor : High";

 desc["francais"] = "
Le modem ADSL Alcatel distant n'a pas de mot de passe.

Un pirate peut s'y connecter et le reconfigurer de telle sorte
qu'il vous soit impossible d'utiliser votre connection ADSL
ni de le reconfigurer.

Solution : faites un telnet sur ce modem et mettez un mot de
passe immédiatement

Facteur de risque : Elevé";

   script_description(english:desc["english"]);
 
   summary["english"] = "Logs into the remote Alcatel ADSL modem";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
   script_family(english:"Misc.", francais:"Divers");
   script_require_ports(23);
 
   exit(0);
}

port = 23; # alcatel's ADSL modem telnet module can't bind to something else

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
   r = recv(socket:soc, length:160);
   if("User : " >< r)
   {
     s = string("\r\n");
     send(socket:soc, data:s);
     r = recv(socket:soc, length:2048);
     if("ALCATEL ADSL" >< r)security_hole(port);
   }
   close(soc);
 }
}
