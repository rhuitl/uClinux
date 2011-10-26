#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
# To: BUGTRAQ@SECURITYFOCUS.COM
# Subject: sendmail -bt negative index bug...
# From: Michal Zalewski <lcamtuf@DIONE.IDS.PL>
# Date: Sun, 8 Oct 2000 15:12:46 +0200 
#

if(description)
{
 script_id(10809);
 script_version ("$Revision: 1.11 $");
 
 name["english"] = "Sendmail -bt option";
 name["francais"] = "Option -bt de sendmail";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote sendmail server, according to its version number,
may be vulnerable to the -bt overflow attack which
allows any local user to execute arbitrary commands as root.

Solution : upgrade to the latest version of Sendmail
Risk factor : High
Note : This vulnerability is _local_ only"; 

	

 desc["francais"] = "
Le serveur sendmail distant, d'après son numéro de version,
est vulnérable à un dépassement de buffer par l'option -bt,
permettant à n'importe quel utilisateur local d'executer
des commandes en tant que root.

Solution : mettez à jour sendmail
Facteur de risque : Elevé
Note : cette vulnérabilité est locale uniquement";

 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Checks the version number"; 
 summary["francais"] = "Vérification du numéro de série de sendmail";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes","smtpserver_detect.nasl");
 script_require_keys("SMTP/sendmail");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");
include("global_settings.inc");

if ( report_paranoia > 1 ) exit(0);


port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port: port);

if(banner && "Switch-" >!< banner )
{
 if(egrep(pattern:".*Sendmail.*((8\.(([0-9]\..*)|(10\..*)|(11\.[0-2])))|SMI-8\.).*",
	string:banner))
 	security_hole(port);
}
