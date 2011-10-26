#
# This script was written by Renaud Deraison <deraison@nessus.org>
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(10465);
 script_bugtraq_id(1469);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0670");
 name["english"] = "CVSWeb 1.80 gives a shell to cvs committers";
 name["francais"] = "CVSWeb 1.80 donne un shell aux commiters";
 script_name(english:name["english"], francais:name["francais"]);
 
 
desc["english"] = "
The remote cvsweb is older or as old as version 1.85.

This version allows a cvs committer to execute arbitrary
commands on your server, with the privileges of the
HTTPd process.

Solution : upgrade to version 1.86 (http://stud.fh-heilbronn.de/~zeller/cgi/cvsweb.cgi/)
Risk factor : High";



desc["francais"] = "
Le cvsweb distant est plus vieux ou aussi vieux que la
version 1.85.

Cette version permet à un commiter d'executer des commandes
arbitraires sur votre serveur, avec les privileges du
serveur web.

Solution : mettez ce cgi à jour en version 1.86 (http://stud.fh-heilbronn.de/~zeller/cgi/cvsweb.cgi/)
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks if CVSWeb is present and gets its version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"],
 		francais:family["francais"]);
 script_dependencie("find_service.nes", "cvsweb_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
port = get_http_port(default:80);

 name = string("www/", port, "/cvsweb/version");
 version = get_kb_item(name);
 if(version)
 {
 if(ereg(pattern:"^1\.([0-7].*|8[0-5])[^0-9]",
         string:version))
	 	security_hole(port);
 }
