#
# (C) Tenable Network Security
#
#
# Ref:
#  Date: Tue, 8 Jun 2004 13:41:11 +0200 (CEST)
#  From: Fernando Sanchez <fer@ceu.fi.udc.es>
#  To: bugtraq@securityfocus.com
#  Subject: U.S. Robotics Broadband Router 8003 admin password visible


if(description)
{
 script_id(12272);
 script_bugtraq_id(10490);
 script_version("$Revision: 1.2 $");
 name["english"] = "US Robotics Disclosed Password Check";
 script_name(english:name["english"]);
 desc["english"] = "
Synopsis :

The remote web server is affected by an information disclosure issue. 

Description :

The remote host appears to be a US Robotics Broadband router. 

The device's administrator password is stored as plaintext in a
Javascript function in the file '/menu.htm', which can be viewed by
anyone. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2004-06/0109.html

Solution: 

Disable the webserver or filter the traffic to the webserver via an 
upstream firewall.

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);

 summary["english"] = "US Robotics Password Check";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


# start check


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0); 

req = http_get(item:"/menu.htm", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if ( res == NULL ) exit(0);

if (
  "function submitF" >< res &&
  "loginflag =" >< res &&
  "loginIP = " >< res &&
  "pwd = " >< res 
) {
  security_hole(port);
  set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
}

