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
 script_id(11088);
 script_bugtraq_id(3898);
 script_cve_id("CVE-2001-0715");
 script_version ("$Revision: 1.9 $");
 
 name["english"] = "Sendmail debug mode leak";
 name["francais"] = "Fuite d'information dans le mode debug de sendmail";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
According to the version number of the remote mail server, 
a local user may be able to obtain the complete mail configuration
and other interesting information about the mail queue even if
he is not allowed to access those information directly, by running
	sendmail -q -d0-nnnn.xxx
where nnnn & xxx are debugging levels.

If users are not allowed to process the queue (which is the default)
then you are not vulnerable.

Solution : upgrade to the latest version of Sendmail or 

do not allow users to process the queue (RestrictQRun option)
Risk factor : Low
Note : This vulnerability is _local_ only"; 


 desc["francais"] = "
D'après le numéro de version du serveur sendmail distant, 
un utilisateur local peut obtenir des informations sur la configuration
du courrier et sur l'état de la file d'attente même s'il n'y a pas
accès directement, en lançant :
	send -q d0-nnnn.xxx
où nnnn et xxx sont des niveaux de débogage.

Si votre système ne permet pas aux utilisateurs de traiter
la file d'attente (ce qui est le cas par défaut), vous n'êtes pas 
vulnérable.

Solution : mettez à jour sendmail or interdisez aux utilisateurs
de toucher à la file d'attente (option RestrictQRun)

Facteur de risque : Très faible / nul
Note : cette vulnérabiité est locale uniquement";

 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Checks the version number for 'debug mode leak'"; 
 summary["francais"] = "Vérification du numéro de série de sendmail pour la 'fuite d'informations en mode debug'";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
 		  francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes","smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
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
