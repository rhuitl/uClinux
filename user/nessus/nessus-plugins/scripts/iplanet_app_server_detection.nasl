#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
#
# This plugin is (C) Renaud Deraison
#


if(description)
{
 script_id(11402);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "iPlanet Application Server Detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin detects if the remote host is running Sun ONE Application
Server (formely known as iPlanet Application Server), and the prefix the 
applications run under.

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Sun ONE Application Server detection";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "DDI_Directory_Scanner.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


#if(http_is_dead(port:port))exit(0);

dirs = get_kb_list(string("www/", port, "/content/directories"));
if(isnull(dirs)) dirs = make_list("/NASApp");
else dirs = make_list("/NASApp", dirs);


# First, we search for an iPlanet Application server.
foreach d (dirs)
{
req = http_get(item:string(d, "/nessus/"), port:port);
res = http_keepalive_send_recv(port:port, data:req);

#
# Post-SP1 replies with a "200 OK" error code, followed by
# an error saying 'GX Error (GX2GX) (blah blah)'
#
if( (("ERROR: Unknown Type of Request" >< res)) ||
     ("GX Error (GX2GX)" >< res))
 {
  set_kb_item(name:string("www/", port, "/SunOneApplicationServer/prefix"),
  	      value:d);
  report = "
A Sun ONE Application Server (aka iPlanet Application Server) seems to operate
on this host, after the suffix '" + d + "'";
  security_note(port:port, data:report);	    
  exit(0);
 }
}

