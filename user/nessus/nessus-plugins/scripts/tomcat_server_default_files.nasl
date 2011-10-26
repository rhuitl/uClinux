#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(12085);
  script_version ("$Revision: 1.4 $");
# script_bugtraq_id();
# script_cve_id("");

 name["english"] = "Apache Tomcat servlet/JSP container default files ";
 script_name(english:name["english"]);
 
 desc["english"] = "
The Apache Tomcat servlet/JSP container has default files installed.

These files should be removed as they may help an attacker to guess the
exact version of the Apache Tomcat which is running on this host and may 
provide other useful information.

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Apache Tomcat default files ";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004 David Kyger");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

warning = string("

Default files, such as documentation, default Servlets and JSPs were found on 
the Apache Tomcat servlet/JSP container.  

Solution: Remove default files, example JSPs and Servlets from the Tomcat 
Servlet/JSP container. 

These files should be removed as they may help an attacker to guess the
exact version of Apache Tomcat which is running on this host and may provide 
other useful information.

The following default files were found :");

port = get_http_port(default:8080);
if (!port) exit(0);

if(get_port_state(port))
 {
  pat1 = "The Jakarta Project";
  pat2 = "Documentation Index";
  pat3 = "Examples with Code";
  pat4 = "Servlet API";
  pat5 = "Snoop Servlet";
  pat6 = "Servlet Name";
  pat7 = "JSP Request Method";
  pat8 = "Servlet path";
  pat9 = "session scoped beans";
  pat9 = "Java Server Pages";
  pat10 = "session scoped beans";
  

  fl[0] = "/tomcat-docs/index.html";
  fl[1] = "/examples/servlets/index.html";
  fl[2] = "/examples/servlet/SnoopServlet";
  fl[3] = "/examples/jsp/snp/snoop.jsp";
  fl[4] = "/examples/jsp/index.html";

  for(i=0;fl[i];i=i+1) {
    req = http_get(item:fl[i], port:port);
    buf = http_keepalive_send_recv(port:port, data:req);
    if ( buf == NULL ) exit(0);
    if ((pat1 >< buf && pat2 >< buf) || (pat3 >< buf && pat4 >< buf) || (pat5 >< buf && pat6 >< buf) || (pat7 >< buf && pat8 >< buf) || (pat9 >< buf && pat10 >< buf)) {
     warning = warning + string("\n", fl[i]);
     flag = 1;
     }
   }
    if (flag > 0) { 
     warning += '\n\nRisk factor : Low';
     security_warning(port:port, data:warning);
    }
}
