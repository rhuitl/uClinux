#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10455);
 script_bugtraq_id(1285);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2000-0488");
 name["english"] = "Buffer Overrun in ITHouse Mail Server v1.04";
 name["francais"] = "Dépassement de buffer dans ITHouse Mail Server v1.04";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote SMTP server is ITHouse Mail Server. 
Versions <= 1.04 of this server are vulnerable to
a buffer overrun which happens during the delivery
routine of the mails if an attacker has sent a 
message with a too long To: field.

An attacker may use this flaw to execute arbitrary
code on this host.

*** Note : we could not check the version number of
*** the server, so this item may be a false positive. 

Solution : Contact your vendor for the latest software release.
Risk factor : High";



 desc["francais"] = "
Le serveur SMTP distant est ITHouse Mail Server.
Les versions inférieures ou égales à la version 1.04
sont vulnérables à un dépassement de buffer ayant lieu
durant la routine de livraison du mail si un pirate
a envoyé un mail avec un champ To: trop long.

Un pirate peut utiliser ce problème pour executer
du code arbitraire sur ce système.

*** Note : il est impossible de vérifier le numéro de version
*** de ce server à distance, donc ce message peut etre
*** une fausse alerte.

Solution : mettez-le à jour en une plus récente version
Facteur de rique : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 
 summary["english"] = "Checks if the remote smtp server is ITHouse Mail Server"; 
 summary["francais"] = "Vérifie si le serveur smtp est ITHouse Mail Server";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 
 script_dependencie("find_service.nes");
 script_require_ports("Services/smtp", 25);
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
 data = get_smtp_banner(port:port);
 if(!data)exit(0);
 if(egrep(string:data,
 	 pattern:".*IT House Mail Server.*"))
	 	security_hole(port);
}
