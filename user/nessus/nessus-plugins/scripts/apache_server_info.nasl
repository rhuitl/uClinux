#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# Licence : GPL v2
#

if(description)
{
 script_id(10678);
 script_version ("$Revision: 1.14 $");
 name["english"] = "Apache /server-info accessible";
 name["francais"] = "Apache /server-info accessible";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Requesting the URI /server-info gives information about
your Apache configuration.

Risk factor : Low
Solution : 
If you don't use this feature, comment the appropriate section in
your httpd.conf file. If you really need it, limit its access to
the administrator's machine.";

 script_description(english:desc["english"]);
 
 summary["english"] = "Make a request like http://www.example.com/server-info";
 summary["francais"] = "Fait une requête du type http://www.example.com/server-info";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 StrongHoldNet",
		francais:"Ce script est Copyright (C) 2001 StrongHoldNet");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
str = "Apache Server Information";

if(get_port_state(port) )
{
  buffer = http_get(item:"/server-info", port:port);
  data = http_keepalive_send_recv(port:port, data:buffer);
  if( str >< data )
  {
   security_warning(port);
  }
}
