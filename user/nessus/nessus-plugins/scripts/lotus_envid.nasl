#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# and was modified and tested by Vanja Hrustic <vanja@relaygroup.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10543);
 script_bugtraq_id(1905);
 script_cve_id("CVE-2000-1047");
 script_version ("$Revision: 1.17 $");

 
 name["english"] = "Lotus Domino SMTP overflow";
 name["francais"] = "Dépassement de buffer dans le serveur SMTP Domino";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote Domino SMTP server is vulnerable to 
a buffer overflow when supplied a too long
ENVID variable within a MAIL FROM command.

An attacker may use this flaw to prevent Domino
services from working properly, or to execute arbitrary 
code on this host.

Solution : Upgrade to Lotus Notes/Domino 5.0.6
Risk factor : High";




 desc["francais"] = "
Le serveur SMTP Domino distant est vulnérable à 
un dépassement de buffer lorsqu'un utilisateur 
donne un argument trop long à la variable ENVID.

Un pirate peut utiliser ce problème pour empecher
les services domino de fonctionner, ou bien meme
executer du code arbitraire sur cette machine.

Solution : Mettez à jour votre serveur en Lotus Notes/Domino 5.0.6
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Determines if the remote Domino server is vulnerable to a buffer overflow";
 summary["francais"] = "Determines if the remote Domino server is vulnerable to a buffer overflow";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes",
 		    "smtp_settings.nasl");
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;

if(get_port_state(port))
{
  soc = open_sock_tcp(port);
  if(soc)
  {
    r = smtp_recv_banner(socket:soc);
    if(!r)exit(0);
    
    if("omino" >< r)
    {
    domain = get_kb_item("Settings/third_party_domain");
    req = string("HELO ", domain, "\r\n");
    send(socket:soc, data:req);
    r  = recv_line(socket:soc, length:4096);

    req = string("MAIL FROM: <nessus@", domain, "> ENVID=", crap(300), "\r\n");
    send(socket:soc, data:req);
    r = recv_line(socket:soc, length:4096);

    if(ereg(pattern:"^250 ", string:r))
        security_hole(port);
    }
    close(soc);
   }
}
