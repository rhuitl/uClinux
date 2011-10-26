#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10687);
 script_version ("$Revision: 1.13 $");
 
 name["english"] = "Too long POST command";
 script_name(english:name["english"]);
 
 desc["english"] = "
It *may* be possible to make this web server execute
arbitrary code by sending it a too long argument to
a POST command.

Risk factor : High

Solution : Upgrade your web server.";
 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Web server buffer overflow";
 summary["francais"] = "Dépassement de buffer dans un serveur web";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
# All the www_too_long_*.nasl scripts were first declared as 
# ACT_DESTRUCTIVE_ATTACK, but many web servers are vulnerable to them:
# The web server might be killed by those generic tests before Nessus 
# has a chance to perform known attacks for which a patch exists
# As ACT_DENIAL are performed one at a time (not in parallel), this reduces
# the risk of false positives.
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
  script_require_ports("Services/www",80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

if(http_is_dead(port:port))exit(0);

sock = http_open_socket(port);
mystr = http_get(item:"/", port:port);
send(socket:sock, data:mystr);
rcv = http_recv(socket:sock);
if(!rcv) exit(0);
http_close_socket(sock);

soc = http_open_socket(port);
if(!soc)exit(0);
req = string("/", crap(4096));
req = http_post(item:req, port:port);
send(socket:soc, data:req);
r = http_recv(socket:soc);
http_close_socket(soc);

if (http_is_dead(port: port))
{
	security_hole(port);
	set_kb_item(name:"www/too_long_url_crash", value:TRUE);
}
