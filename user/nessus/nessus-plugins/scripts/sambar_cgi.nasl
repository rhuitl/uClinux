#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10246);
 script_bugtraq_id(1002);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0213");
 
 name["english"] = "Sambar Web Server CGI scripts";
 name["francais"] = "Scripts CGI du serveur web Sambar";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
At least one of these CGI scripts is installed :

	hello.bat
	echo.bat
	
They allow any attacker to execute commands with the privileges of the web 
server process.	

Solution : Delete all the *.bat files from your cgi-bin/ directory
Risk factor : High";


 desc["francais"] = "
Au moins un de ces CGI est installé :

	hello.bat
	echo.bat
	
Ils permettent à n'importe quel pirate d'executer
des commandes arbitraires sur ce système, avec
les privilèges du serveur web.

Solution : effacez tous les fichiers .bat du
           répèrtoire cgi-bin/        
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/{hello,echo}.bat";
 summary["francais"] = "Vérifie la présence de /cgi-bin/{hello,echo}.bat";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port ( default:port );
if(!port) exit(0);

if (is_cgi_installed_ka(item:"hello.bat", port:port) ||
    is_cgi_installed_ka(item:"echo.bat", port:port))
  security_hole(port);

