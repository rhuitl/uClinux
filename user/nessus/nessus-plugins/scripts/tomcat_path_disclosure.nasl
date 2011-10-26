#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10807);
 script_bugtraq_id(1531);
script_cve_id("CVE-2000-0759");
 script_version ("$Revision: 1.17 $");
 name["english"] = "Jakarta Tomcat Path Disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
Tomcat will reveal the physical path of the 
webroot when asked for a .jsp file using a specially
crafted request.

An attacker may use this flaw to gain further knowledge
about the remote filesystem layout.

Solution : Upgrade to a later software version.
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for Tomcat Path Disclosure Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("www/apache");
 exit(0);
}

# According to this message:
#   Date:  Thu, 22 Nov 2001 17:32:20 +0800
#   From: "analysist" <analysist@nsfocus.com>
#   To: "bugtraq@securityfocus.com" <bugtraq@securityfocus.com>
#   Subject: Hi
# Jakarta Tomcat also reveals the web server install path if we get:
# /AAA...A.jsp  (223 x A)
# /~../x.jsp


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
if(get_port_state(port))
{ 
 req = http_get(item:string("/:/x.jsp"), port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if ( ! r ) exit(0);
 
 if("Server: Apache Tomcat/3" >< r)
  {
  path = ereg_replace(pattern:".*HTTP Status 404 - ([^<]*) .The.*",
		    string:r,
		    replace:"\1");
  if(ereg(string:path, pattern:"[A-Z]:\\.*", icase:TRUE))security_warning(port);
  }
}
