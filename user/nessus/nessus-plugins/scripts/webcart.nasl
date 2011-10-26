#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Written after the advisory of MindSec
#

if(description)
{
 script_id(10298);
 script_bugtraq_id(2281);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-0610");
 name["english"] = "Webcart misconfiguration";
 name["francais"] = "Mauvaise configuration de Webcart";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "At least one of these file or directories is
world readable :

			/webcart/orders/
			/webcart/orders/import.txt
			/webcart/carts/
			/webcart/config/
			/webcart/config/clients.txt
			/webcart-lite/orders/import.txt
			/webcart-lite/config/clients.txt
			
This misconfiguration may allow an attacker to gather
the credit card numbers of your clients.

Solution : Do not make directories world readable.

Risk factor : High";


 desc["francais"] = "Au moins un de ces fichiers ou dossier
est lisible :

			/webcart/orders/
			/webcart/orders/import.txt
			/webcart/carts/
			/webcart/config
			/webcart/config/clients.txt
			/webcart-lite/orders/import.txt
			/webcart-lite/config/clients.txt

Ce problème de configuration peut permettre à un pirate d'obtenir
le numéro de carte de crédit de vos clients.

Solution : Ajoutez une ACL qui rend ces fichiers et dossiers illisibles.

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the webcart misconfiguration";
 summary["francais"] = "Vérifie la mauvaise configuration des webcart";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);



c[0] = "/webcart/orders/";
c[1] = "/webcart/orders/carts/.txt";
c[2] = "/webcart/config/";
c[3] = "/webcart/carts/";
c[4] = "/webcart/config/clients.txt";
c[5] = "/webcart-lite/config/clients.txt";
c[6] = "/webcart-lite/orders/import.txt";
c[7] = "";

for(i = 0 ; c[i] ; i = i + 1)
{
 if(is_cgi_installed_ka(item:c[i], port:port)){
 	security_hole(port);
	exit(0);
	}
}
