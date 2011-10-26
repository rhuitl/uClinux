#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11046);
 script_cve_id("CVE-2002-2006");
 script_bugtraq_id(4575);
 script_version("$Revision: 1.17 $");
 name["english"] = "Apache Tomcat TroubleShooter Servlet Installed";
 name["francais"] = "Apache Tomcat TroubleShooter Servlet Installed";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

The remote Apache Tomcat Server is vulnerable to cross script scripting and 
path disclosure issues.

Description :

The default installation of Tomcat includes various sample jsp pages and 
servlets.
One of these, the 'TroubleShooter' servlet, discloses various information about 
the system on which Tomcat is installed. This servlet can also be used to 
perform cross-site scripting attacks against third party users.

Solution : 

Example files should not be left on production servers.

See also : 

http://www.osvdb.org/displayvuln.php?osvdb_id=849

Risk factor :

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests whether the Apache Tomcat TroubleShooter Servlet is installed";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes","http_version.nasl");
 script_require_ports("Services/www", 80, 8080);
 script_require_keys("www/apache");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(! port || ! get_port_state(port)) exit(0);

sig = get_kb_item("www/hmap/"  + port  + "/description");
if ( sig && "Apache" >!< sig && "Tomcat" >!<  sig ) exit(0);

req = http_get(item:"/examples/servlet/TroubleShooter", port:port);
r =   http_keepalive_send_recv(port:port, data:req);
confirmed = string("TroubleShooter Servlet Output"); 
confirmed_too = string("hiddenValue");
if ((confirmed >< r) && (confirmed_too >< r)) 	
	{
 		security_note(port);
	}
