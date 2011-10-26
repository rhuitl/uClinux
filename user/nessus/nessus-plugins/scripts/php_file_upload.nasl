#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10513);
 script_bugtraq_id(1649);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2000-0860");
 name["english"] = "php file upload";
 name["francais"] = "php file upload";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
A version of php which is older than 3.0.17
or 4.0.3 is running on this host.

If a php service that allows users to upload files 
and then display their content is running on this host,
an attacker may be able to read arbitrary files from the server.

Solution : upgrade to php 3.0.17 or 4.0.3, and see also 
	   http://www.php.net/manual/language.variables.predefined.php

Risk factor : High";


 desc["francais"] = "
Une version de php plus vieille que la 3.0.17 ou que la 4.0.3
tourne sur ce serveur.

Si un service php permettant aux utilisateurs d'uploader des fichiers
puis d'afficher leur contenu tourne sur ce système, alors un pirate
est en mesure de lire des fichiers arbitraires sur ce serveur.

Solution : mettez php à jour en version 3.0.17 ou 4.0.3, et allez voir
 	   http://www.php.net/manual/language.variables.predefined.php

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of PHP";
 summary["francais"] = "Vérifie la version de PHP";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);



if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner)exit(0);
 if(egrep(pattern:"(.*PHP/3\.0\.((1[0-6])|([0-9]([^0-9]|$))))|(.*PHP/4\.0\.[0-2]([^0-9]|$))",
          string:banner))
 {
   security_hole(port);
 }
}
 
