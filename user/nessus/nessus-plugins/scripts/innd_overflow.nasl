#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10436);
 script_bugtraq_id(1316);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2000-0472");
 name["english"] = "INN version check (2)";
 name["francais"] = "Vérification de la version de INN (2)";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote version of INN is 
between 2.0 and 2.2.2

There is a known security flaw
in this version of INN which
may allow an attacker to execute
arbitrary code on this server
is the option 'verifycancels' is enabled
in inn.conf

Solution : upgrade to version 2.2.3 or make sure
that the option verifycancel is disabled on this
server.

Risk factor : High";

 desc["francais"] = "
La version de INN est comprise entre 2.0
et 2.2.2.

Il y a un problème de sécurité dans la branche
2.x de INN qui peut permettre à un intrus
d'executer du code arbitraire sur ce système
pour peut que l'option 'verifycancels' soit activée
dans inn.conf

Solution : mettez le serveur à jour en 2.2.3 ou bien
assurez vous que l'option verifycancel n'est pas
activée dans inn.conf

Facteur de risque : Elevé";



 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks INN version";
 summary["francais"] = "Vérifie la version d'INN";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/nntp", 119);
 exit(0);
}




port = get_kb_item("Services/nntp");
if(!port) port = 119;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
  if(soc)
  {
   # check for INN 2.0.0 to 2.2.2
   
   r = recv_line(socket:soc, length:1024);
    if(ereg(string:r, pattern:"^20[01] .* INN 2\.(([0-1]\..*)|(2\.[0-2])) .*$"))
    {
      security_warning(port);
    }
  }
}
