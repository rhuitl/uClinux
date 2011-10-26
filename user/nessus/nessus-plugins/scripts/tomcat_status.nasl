#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11218);
# script_cve_id("CVE-MAP-NOMATCH");
 script_version ("$Revision: 1.4 $");
 name["english"] = "Tomcat /status information disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
Requesting the URI /status gives information about
the currently running Tomcat.

It also allows anybody to reset (ie: permanently delete) the current
statistics.

Risk factor : Low 

Solution : If you don't use this feature, comment the appropriate section in
your httpd.conf file. If you really need it, limit its access to
the administrator's machine.";

 script_description(english:desc["english"]);
 
 summary["english"] = "Makes a request like http://www.example.com/server-status";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 StrongHoldNet",
		francais:"Ce script est Copyright (C) 2003 StrongHoldNet");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
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


if(get_port_state(port))
{
  buffer = http_get(item:"/status", port:port);
  data = http_keepalive_send_recv(port:port, data:buffer);
  if( ("Status information for" >< data) && ("<a href='jkstatus?scoreboard.reset'>reset</a>" >< data) )
   security_warning(port);
}

