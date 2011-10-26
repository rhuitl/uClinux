#
# This script was written by Sullo (sullo@cirt.net)
#

if(description)
{
 script_id(11220);
 script_version ("$Revision: 1.2 $");
 name["english"] = "Netscape /.perf accessible";
 name["francais"] = "Netscape /.perf accessible";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Requesting the URI /.perf gives information about
the currently running Netscape/iPlanet web server.

Risk factor : Low
Solution : If you don't use this feature, server monitoring should be
disabled in the magnus.conf file or web server admin.";

 script_description(english:desc["english"]);
 
 summary["english"] = "Makes a request like http://www.example.com/.perf";
 summary["francais"] = "Fait une requête du type http://www.example.com/.perf";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Sullo",
		francais:"Ce script est Copyright (C) 2003 Sullo");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/netscape-commerce", "www/netscape-fasttrack", "www/iplanet");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);
str = "ListenSocket";

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buffer = http_get(item:"/.perf", port:port);
  send(socket:soc, data:buffer);
  data = http_recv(socket:soc);
  if( str >< data )
  {
   security_warning(port);
  }
  http_close_socket(soc);
 }
}
