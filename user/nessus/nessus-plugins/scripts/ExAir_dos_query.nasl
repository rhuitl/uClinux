#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 name["english"] = "IIS possible DoS using ExAir's query";
 name["francais"] = "Déni de service possible de IIS en utilisant query de ExAir";
 name["deutsch"] = "Moeglicher IIS DoS-Angriff mittels ExAir's query";
  
 script_name(english:name["english"], francais:name["francais"], deutsch:name["deutsch"]);
 script_id(10003);
 script_bugtraq_id(193);
 script_version ("$Revision: 1.28 $");
 script_cve_id("CVE-1999-0449");
 
 desc["english"] = "
IIS comes with the sample site 'ExAir'. Unfortunately, one of its pages,
namely /iissamples/exair/search/query.asp, may be used to make IIS hang,
thus preventing it from answering legitimate client requests.

Solution : Delete the 'ExAir' sample IIS site.

Risk factor : High";


 desc["francais"] = "IIS est livré avec un site de démonstration : 'ExAir'.
Hélas, une des ses pages, /iissamples/exair/search/query.asp, peut
etre utilisée pour bloquer IIS, l'empechant ainsi de répondre aux
connections de clients légitimes.

Facteur de risque : Elevé. 

Solution : Supprimez le site de démonstration 'ExAir'";

 desc["deutsch"] = "IIS wird mit der Beispielsite ExAir installiert.
Ungluecklicherweise kann durch Aufruf einer der Seiten, naemlich
	/iissamples/exair/search/query.asp
der komplette IIS aufgehaengt werden.

Risiko Fakrot:  Hoch	

Loesung:	Loeschen Sie die 'ExAir' Beispiel IIS-Site.";

 script_description(english:desc["english"], francais:desc["francais"], deutsch:desc["deutsch"]);
 
 summary["english"] = "Determines the presence of an ExAir asp";
 summary["francais"] = "Détermine la présence d'une page asp de ExAir";
 summary["deutsch"] = "Ueberprueft die Existent einer ExAir asp-Seite";

 script_summary(english:summary["english"], francais:summary["francais"], deutsch:summary["deutsch"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison",
		deutsch:"Dieses Script ist Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 family["deutsch"] = "CGI Sicherheitsluecken";

 script_family(english:family["english"], francais:family["francais"], deutsch:family["deutsch"]);
 
 script_dependencie("find_service.nes", "http_version.nasl");
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
if ( ! can_host_asp(port:port) ) exit(0);


cgi = "/iissamples/exair/search/query.asp";
res = is_cgi_installed_ka(item:cgi, port:port);
if( res )security_hole(port);

