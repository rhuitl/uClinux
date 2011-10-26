#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#      Also covers BugtraqID: 5194 (same Advisory ID#: wp-02-0008)
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11041);
 script_bugtraq_id(5193);
 script_version("$Revision: 1.19 $");
 script_cve_id("CVE-2002-0682");
 
 name["english"] = "Apache Tomcat /servlet Cross Site Scripting";
 name["francais"] = "Apache Tomcat /servlet Cross Site Scripting";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

The remote Apache Tomcat web server is vulnerable to a cross site scripting 
issue.

Description :

Apache Tomcat is the servlet container that is used in the official Reference 
Implementation for the Java Servlet and JavaServer Pages technologies.

By using the /servlet/ mapping to invoke various servlets / classes it is
possible to cause Tomcat to throw an exception, allowing XSS attacks,e.g:

tomcat-server/servlet/org.apache.catalina.servlets.WebdavStatus/SCRIPTalert(document.domain)/SCRIPT
tomcat-server/servlet/org.apache.catalina.ContainerServlet/SCRIPTalert(document.domain)/SCRIPT
tomcat-server/servlet/org.apache.catalina.Context/SCRIPTalert(document.domain)/SCRIPT
tomcat-server/servlet/org.apache.catalina.Globals/SCRIPTalert(document.domain)/SCRIPT

(angle brackets omitted)

Solution : 

The 'invoker' servlet (mapped to /servlet/), which executes anonymous servlet
classes that have not been defined in a web.xml file should be unmapped.

The entry for this can be found in the /tomcat-install-dir/conf/web.xml file.

See also : 

www.westpoint.ltd.uk/advisories/wp-02-0008.txt

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for Apache Tomcat /servlet XSS Bug";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("www/apache");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
if(!port)exit(0);

if(!get_port_state(port)) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
sig = get_kb_item("www/hmap/"  + port  + "/description");
if ( sig && "Apache" >!< sig && "Tomcat" >!<  sig ) exit(0);

req = http_get(item:"/servlet/org.apache.catalina.ContainerServlet/<SCRIPT>alert(document.domain)</SCRIPT>", port:port);
r = http_keepalive_send_recv(port:port, data:req);
confirmed = string("<SCRIPT>alert(document.domain)</SCRIPT>"); 
confirmed_too = string("javax.servlet.ServletException");
  if ((confirmed >< r) && (confirmed_too >< r)) {
		security_note(port);
}

