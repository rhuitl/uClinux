#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# Licence : GPL v2
#

if(description)
{
 script_id(11930);
 script_version ("$Revision: 1.2 $");
 name["english"] = "Resin /caucho-status accessible";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Requesting the URI /caucho-status gives information about
the currently running Resin java servlet container.

Risk factor : Low
Solution : 
If you don't use this feature, set the content of the '<caucho-status>' element
to 'false' in the resin.conf file.";

 script_description(english:desc["english"]);
 
 summary["english"] = "Makes a request like http://www.example.com/caucho-status";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 StrongHoldNet",
		francais:"Ce script est Copyright (C) 2003 StrongHoldNet");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

req = http_get(item:"/caucho-status", port:port);
r = http_keepalive_send_recv(port:port, data:req);
if ( r == NULL ) exit(0);
  
if("<title>Status : Caucho Servlet Engine" >< r && "%cpu/thread" >< r) {
  security_hole(port:port);
  exit(0);
}

