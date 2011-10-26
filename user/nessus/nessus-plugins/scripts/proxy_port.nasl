#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10193);
 script_version ("$Revision: 1.19 $");
 
 name["english"] = "Usable remote proxy on any port";
 name["francais"] = "Proxy distant utilisable sur n'importe quel port";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = string("The proxy, allows everyone to perform requests 
against arbitrary ports, like 
'GET http://cvs.nessus.org:110'. 
This problem may allow attackers to go through your
firewall, by connecting to sensitive ports like 25 (sendmail) 
using your proxy. In addition to that, your proxy may be used
to perform attacks against other networks.

Solution: reconfigure your proxy so that it only accepts 
connections against non-dangerous ports (> 1024).

Risk factor : High");

 desc["francais"] = string("Le proxy web autorise n'importe qui à se connecter
sur des ports arbitraires, en utilisant des requêtes telles que 
'GET http://cvs.nessus.org:110'. Ce problème peut être source d'ennuis, 
car il peut permettre à des intrus de passer au travers de votre firewall.

Solution : reconfigurez votre proxy afin qu'il n'accepte de se connecter 
que contre des ports non dangereux.

Facteur de risque : Elevé");

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines if we can use the remote web proxy against any port"; 
 summary["francais"] = "Determine si nous pouvons utiliser le proxy web distant contre n'importe quel port";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "Firewalls"; 
 family["francais"] = "Firewalls";
 
 script_family(english:family["english"],
 	       francais:family["francais"]);
 script_dependencie("find_service.nes", "proxy_use.nasl");
 script_require_keys("Proxy/usage");
 script_require_ports("Services/http_proxy", 8080);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/http_proxy");
if(!port) port = 8080;
usable_proxy = get_kb_item("Proxy/usage");
if(usable_proxy)
{
 if(get_port_state(port))
 {
 soc = http_open_socket(port);
 if(soc)
  {
  file = string("http://", get_host_name(), ":25/");
  command = http_get(item:file, port:port);
  send(socket:soc, data:command);
  buffer = recv_line(socket:soc, length:4096);
  if("503" >< buffer){
        http_close_socket(soc);
  	security_hole(port);
	exit(0);
	}
  else {
   if("200" >< buffer)
   {
    #
    # Some stupid servers reply with a 200- code 
    # to say that an error occured...
    #
    headers = http_recv_headers2(socket:soc);
    error1 = http_recv_body(socket:soc, headers:headers, length:0);
    http_close_socket(soc);
    
    soc2 = http_open_socket(port);
    file = string("http://", get_host_name(), ":26");
    command = http_get(item:file, port:port);
    send(socket:soc2, data:command);
    buffer = recv_line(socket:soc2, length:4096);
    if("503" >< buffer){
    	http_close_socket(soc2);
	security_hole(port);
	exit(0);
	}
    else {
     if("200" >< buffer)
     {
      headers = http_recv_headers2(socket:soc);
     error2 = http_recv_body(socket:soc, headers:headers, length:0);
     http_close_socket(soc);
     if(error1 == error2)exit(0);
     else security_hole(port);
     }
    }
   }
  }
  }
 }
}
