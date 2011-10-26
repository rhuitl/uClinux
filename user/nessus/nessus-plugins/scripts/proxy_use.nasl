#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10195);
 script_version ("$Revision: 1.23 $");
 name["english"] = "Usable remote proxy";
 name["francais"] = "Proxy distant utilisable";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = string("
The remote proxy accepts requests coming from the Nessus scanner. 

This allows attackers to gain some anonymity when browsing 
some sensitive sites using your proxy, making the remote sites think that
the requests come from your network.

Solution: Reconfigure the remote proxy so that it only accepts requests coming 
from inside your network.
 
Risk factor : Low / Medium");

 desc["francais"] = string("Le proxy mal configuré accepte des 
requêtes provenant de n'importe où, ce qui peut permettre à des intrus 
de browser le web avec un certain anonymat, lorsqu'ils utilisent ce proxy,
en faisant croire aux sites distants que les requêtes proviennent de 
votre réseau. Ce problème leur permet aussi de gacher votre bande 
passante.

Solution : reconfigurez votre proxy afin qu'il n'accepte que les 
requêtes provenant de votre réseau interne.

Facteur de risque : Faible/Moyen");
 
 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines if we can use the remote web proxy"; 
 summary["francais"] = "Determine si nous pouvons utiliser le proxy web distant";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "Firewalls"; 
 family["francais"] = "Firewalls";
 
 script_family(english:family["english"],
 	       francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/http_proxy", 3128, 8080);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("misc_func.inc");
include("global_settings.inc");

if ( islocalnet() && report_paranoia < 2 ) exit(0);

ports = add_port_in_list(list:get_kb_list("Services/http_proxy"), port:3128);
ports = add_port_in_list(list:ports, port:8080);


foreach port (ports)
{
soc = open_sock_tcp(port);
if(soc)
{
 domain = get_kb_item("Settings/third_party_domain");
 if(domain)
  name = string("www.", domain);
 else 
   name = "www";
   
 req = string("GET / HTTP/1.0\r\nProxy-Connection: Keep-Alive\r\n\r\n");
 send(socket:soc, data:req);
 r = http_recv_headers2(socket:soc);
 
 page = recv(socket:soc, length:50);
 close(soc);
 
 soc = open_sock_tcp(port);
 if (soc)
 {
 command = string("GET http://", name, "/ HTTP/1.0\r\nProxy-Connection: Keep-Alive\r\n\r\n");
 send(socket:soc, data:command);
 buffer = http_recv_headers2(socket:soc);

 if(egrep(pattern:"^HTTP/1\.[01] 200 .*", string:buffer))
 	 	{
		page2 = recv(socket:soc, length:50);
		if(!(page == page2))
			{
 			security_warning(port);
			set_kb_item(name:"Proxy/usage", value:TRUE);
			}
		}
 if(egrep(pattern:"^HTTP/1\.[01] 50[23] .*", string:buffer))
 		{
		security_warning(port);
		set_kb_item(name:"Proxy/usage", value:TRUE);
		}
 close(soc);
 }
 }
}
