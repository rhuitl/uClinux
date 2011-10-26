#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10960);
 script_bugtraq_id(4793);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2002-0892");
 name["english"] = "ServletExec 4.1 ISAPI Physical Path Disclosure";
 name["francais"] = "ServletExec 4.1 ISAPI Physical Path Disclosure";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
 By requesting a non-existent .JSP file, or by invoking the JSPServlet 
 directly and supplying no filename, it is possible to make the ServletExec 
 ISAPI filter disclose the physical path of the webroot.

Solution: 

Use the main ServletExec Admin UI to set a global error page for the entire 
ServletExec Virtual Server.

References: www.westpoint.ltd.uk/advisories/wp-02-0006.txt

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for ServletExec 4.1 ISAPI Path Disclosure";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 req = http_get(item:"/servlet/com.newatlanta.servletexec.JSP10Servlet", port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 confirmed = string("newatlanta");
 confirmedtoo = string("filename"); 
 if ((confirmed >< r) && (confirmedtoo ><r))	
 	security_hole(port);

}

