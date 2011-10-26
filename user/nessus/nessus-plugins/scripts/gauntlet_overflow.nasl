#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10420);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:" 2000-a-0003");
 script_bugtraq_id(1234);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2000-0437");
 
 name["english"] = "Gauntlet overflow";
 name["francais"] = "Dépassement de buffer dans Gauntlet";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It seems that the remote host is vulnerable
to a buffer overflow on port 8999, which may
give a shell access to anyone.

Solution : if the remote host is a Gauntlet firewall, then
see http://www.tis.com/support/cyberadvisory.html, or else
you can probably ignore this alert.

Risk factor : High";



 desc["francais"] = "
Le serveur distant semble etre vulnérable à un dépassement
de buffer sur le port 8999, qui peut donner un shell
à n'importe qui.

Solution : si l'hote distant est un firewall Gauntlet, alors
allez voir http://www.tis.com/support/cyberadvisory.html, sinon
pouvez probablement ignorer ce message

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Overflow in the Gauntlet product line";
 summary["francais"] = "Dépassement de buffer dans la ligne de produits Gauntlet";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports(8999);
 exit(0);
}


port = 8999;
if(get_port_state(port))
{
  soc = open_sock_tcp(port);
  if(soc)
  {
    req = string("10003.http://", crap(10), "\r\n");
    send(socket:soc, data:req);
    r = recv(socket:soc, length:2048);
    close(soc);
    if ( ! r ) exit(0);

    soc = open_sock_tcp(port);
    if ( ! soc ) exit(0);
    req = string("10003.http://", crap(10000), "\r\n");
    send(socket:soc, data:req);
    r = recv(socket:soc, length:2048);
    close(soc);
    if(!r)
    {
      security_hole(port);
    }
  }
}
