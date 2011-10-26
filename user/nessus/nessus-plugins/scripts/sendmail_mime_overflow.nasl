#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10588);
script_cve_id("CVE-1999-0206");
 script_version ("$Revision: 1.9 $");
 
 name["english"] = "Sendmail mime overflow";
 name["francais"] = "Dépassement de buffer dans sendmail";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote sendmail server, according to its version number,
may be vulnerable to the MIME buffer overflow attack which
allows anyone to execute arbitrary commands as root.

Solution : upgrade to the latest version of Sendmail
Risk factor : High"; 
	

 desc["francais"] = "
Le serveur sendmail distant, d'après son numéro de version,
est vulnérable à un dépassement de buffer permettant à
n'importe qui d'executer des commandes en tant que root.

Solution : mettez à jour sendmail
Facteur de risque : Elevé";

 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Checks the version number"; 
 summary["francais"] = "Vérification du numéro de série de sendmail";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);

if(banner && "Switch-" >!< banner )
{
 if(egrep(pattern:".*Sendmail.*8\.8\.[01]/.*", string:banner))
 	security_hole(port);
}
