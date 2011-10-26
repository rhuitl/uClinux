# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# References:
# From: "Michal Zalewski" <lcamtuf@echelon.pl>
# To: bugtraq@securityfocus.com
# CC: sendmail-security@sendmail.org
# Subject: RAZOR advisory: multiple Sendmail vulnerabilities

if(description)
{
 script_id(11087);
 script_bugtraq_id(3378);
 script_cve_id("CVE-2001-0714");
 script_version ("$Revision: 1.8 $");
 
 name["english"] = "Sendmail queue manipulation & destruction";
 name["francais"] = "Manipulation & destruction de la file d'attente de sendmail";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote sendmail server, according to its version number,
might be vulnerable to a queue destruction when a local user
runs
	sendmail -q -h1000

If you system does not allow users to process the queue (which
is the default), you are not vulnerable.

Solution : upgrade to the latest version of Sendmail or 
do not allow users to process the queue (RestrictQRun option)
Risk factor : Low
Note : This vulnerability is _local_ only"; 


 desc["francais"] = "
Le serveur sendmail distant, d'après son numéro de version,
est vulnérable à une destruction de file d'attente lorsqu'un 
utilisateur local lance :
	sendmail -q -h1000

Si votre système ne permet pas aux utilisateurs de traiter
la file d'attente (ce qui est le cas par défaut), vous n'êtes pas 
vulnérables.

Solution : mettez à jour sendmail or interdisez aux utilisateurs
de toucher à la file d'attente (option RestrictQRun)

Facteur de risque : Faible
Note : cette vulnérabiité est locale uniquement";

 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Checks the version number for 'queue destruction'"; 
 summary["francais"] = "Vérification du numéro de série de sendmail pour l'attaque 'destruction de file d'attente'";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
 		  francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes","smtpserver_detect.nasl");
 script_require_keys("SMTP/sendmail","smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port: port);
if(! banner || "Switch-" >< banner ) exit(0);

if(egrep(pattern:".*Sendmail.*8\.(([0-9]\..*)|(1[01]\..*)|(12\.0)).*",
	string:banner))
	security_warning(port);
