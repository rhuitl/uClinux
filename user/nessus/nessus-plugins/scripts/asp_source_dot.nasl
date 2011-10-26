#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10363);
 script_bugtraq_id(1814);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-1999-0253"); 
 name["english"] = "ASP source using %2e trick";
 name["francais"] = "Sources des fichiers ASP en utilisant le %2e";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to get the source code of the remote
ASP scripts by appending %2e at the end
of the request (like GET /default.asp%2e)


ASP source codes usually contain sensitive informations such
as logins and passwords.

Solution :  install all the latest Microsoft Security Patches
	
Risk factor : High";
	
 desc["francais"] = "
Il est possible d'obtenir le code source des fichiers
ASP distants en ajoutant %2e apres le nom du fichier
(comme par exemple GET /default.asp%2e)


Les codes sources ASP contiennent souvent des informations
sensibles telles que des logins et des mots de passe.

Solution : installez tous les derniers patch de sécurité Microsoft
Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "downloads the source of ASP scripts";
 summary["francais"] = "télécharge le code source des fichiers ASP";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "webmirror.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

function check(file)
{
  req = http_get(item:string(file, "%2e"), port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if ( ! r ) exit(0);
  if("Content-Type: application/octet-stream" >< r){
  	security_hole(port);
	return(1);
	}
 return(0);
}

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

if(get_port_state(port))
{
 if(check(file:"/default.asp"))exit(0);
 files = get_kb_list(string("www/", port, "/content/extensions/asp"));
 if(isnull(files))exit(0);
 files = make_list(files);
 check(file:files[0]);
}
