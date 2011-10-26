#
# Michel Arboi <arboi@alussinan.org> hacked asp_source_data.nasl which
# was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# GPL
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# References:
# Date:  Fri, 29 Jun 2001 13:01:21 -0700 (PDT)
# From: "Extirpater" <extirpater@yahoo.com>
# Subject: 4 New vulns. vWebServer and SmallHTTP
# To: bugtraq@securityfocus.com, vuln-dev@securityfocus.com
#

if(description)
{
 script_id(11071);
 script_bugtraq_id(2975);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2001-1248");
 name["english"] = "ASP source using %20 trick";
 name["francais"] = "Sources des fichiers ASP en ajoutant %20";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to get the source code of the remote
ASP scripts by appending %20 at the end
of the request (like GET /default.asp%20)


ASP source code usually contains sensitive information such
as logins and passwords.

Solution :  install all the latest security patches
	
Risk factor : High";
	
 desc["francais"] = "
Il est possible d'obtenir le code source des fichiers
ASP distants en ajoutant %20 après le nom du fichier
(comme par exemple GET /default.asp%20)


Les codes sources ASP contiennent souvent des informations
sensibles telles que des logins et des mots de passe.

Solution : installez tous les derniers patch de sécurité
Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "downloads the source of ASP scripts";
 summary["francais"] = "télécharge le code source des fichiers ASP";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 # In fact, Renaud wrote more than halt of this script!
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
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
  req = http_get(item:string(file, "%20"), port:port);
  r   = http_keepalive_send_recv(port:port, data:req);
  if ( ! r ) exit(0);
  if ( ! ereg(pattern:"^HTTP/.* 200 .*", string:r) ) exit(0);
  if("Content-Type: application/octet-stream" >< r){
  	security_hole(port);
	return(1);
	}
  if (("<%" >< r) && ("%>" >< r)) {
	security_hole(port);
	return(1);
  }
 return(0);
}


port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

if(check(file:"/default.asp"))exit(0);
files = get_kb_list(string("www/", port, "/content/extensions/asp"));
if(isnull(files))exit(0);
files = make_list(files);
check(file:files[0]); 
