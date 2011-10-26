#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 name["english"] = "ColdFusion Vulnerability";
 name["francais"] = "Vulnérabilité ColdFusion";
 name["deutsch"] = "ColdFusion Sicherheitsluecke";
 
 script_name(english:name["english"], francais:name["francais"], deutsch:name["deutsch"]);
 script_id(10001);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"1999-b-0001");
 script_bugtraq_id(115);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-0455", "CVE-1999-0477");
 
 desc["english"] = "
It is possible to read arbitrary files on the remote
server using the CGI :

	/cfdocs/expeval/exprcalc.cfm
	
This CGI allows anyone to view, delete and upload 
anything on the remote ColdFusion Application
server.


See also : 
	http://www.l0pht.com/advisories/cfusion.txt


Solution : Allaire has posted a patch to this 
vulnerability. This is currently available at:
http://www.allaire.com/handlers/index.cfm?ID=8727&Method=Full

In addition to this patch, it is recommended that 
the documentation and example code not be stored 
on production servers.

Risk factor : High";

	
 desc["francais"] = "
Il est possible de lire des fichiers arbitraires 
en utilisant le CGI :
	/cfdocs/expeval/ExprCalc.cfm
	
Celui-ci permet à n'importe qui de lire, effacer 
et uploader des fichiers arbitraires sur la machine 
distante.

Voir aussi :
	http://www.l0pht.com/advisories/cfusion.txt	

Solution :
Allaire a fait un patch, disponible à :
http://www.allaire.com/handlers/index.cfm?ID=8727&Method=Full
De plus, il n'est pas recommandé de laisser des
programmes d'exemples sur un serveur de production.

Facteur de risque : Elevé";

desc["deutsch"] = "
Es ist moeglich, durch Aufruf des CGI-Programmes:

	/cfdocs/expeval/exprcalc.cf 

beliebige Dateien auf dem Server zu lesen.
Dieses CGI erlaubt jedermann das lesen, loeschen und hochladen
von Dateien auf den Coldfusion Server.

Weitere Infos unter:
	http://www.l0pht.com/advisories/cfusion.txt

Loesung:
Allaire hat einen Patch fuer das Problem herausgegeben. Man bekommt
ihn unter:
http://www.allaire.com/handlers/index.cfm?ID=8727&Method=Full

Man sollte generell keine Beispieldateien und die Dokumentation auf
Servern im produktiven Betrieb herumliegen lassen.

Risiko Faktor: Hoch";

 script_description(english:desc["english"], francais:desc["francais"], deutsch:desc["deutsch"]);
 
 summary["english"] = "Checks for a ColdFusion vulnerability";
 summary["francais"] = "Vérifie la présence de la vulnérabilité ColdFusion";
 summary["deutsch"] = "Ueberprueft auf ColdFusion Sicherheitsluecke";

 script_summary(english:summary["english"], francais:summary["francais"], deutsch:summary["deutsch"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison", 
		deutsch:"Dieses script ist Copyright (C) 1999 Renaud Deraision");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 family["deutsch"] = "CGI Sicherheitsluecken";
 script_family(english:family["english"], francais:family["francais"], deutsch:family["deutsch"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

#
# The script code starts here
#

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

cgi = "/cfdocs/expeval/ExprCalc.cfm?OpenFilePath=c:\winnt\win.ini";
cgi2 = "/cfdocs/expeval/ExprCalc.cfm?OpenFilePath=c:\windows\win.ini";
y = is_cgi_installed_ka(item:cgi, port:port);
if(!y){
	y = is_cgi_installed_ka(item:cgi2, port:port);
	cgi = cgi2;
	}
	
	
if(y){
	req = http_get(item:cgi, port:port);
	res = http_keepalive_send_recv(port:port, data:req);
  	if ( res == NULL ) exit(0);
	if( "[fonts]" >< res )
		security_hole(port);
	}
