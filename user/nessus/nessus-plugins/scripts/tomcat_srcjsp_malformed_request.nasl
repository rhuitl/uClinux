#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(12123);
  script_bugtraq_id(4876);
  script_version ("$Revision: 1.3 $");
# script_cve_id("");

 name["english"] = "Apache Tomcat source.jsp malformed request information disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The source.jsp file, distributed with Apache Tomcat server, will
disclose information when passed a malformed request. As a result,
information such as the web root path and directory listings could
be obtained.

Example: http://target/examples/jsp/source.jsp?? - reveals the web root
         http://target/examples/jsp/source.jsp?/jsp/ - reveals the contents of the jsp directory

See also: http://www.securityfocus.com/bid/4876

Solution: Remove default files from the web server

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the Tomcat source.jsp malformed request vulnerability";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004 David Kyger");
 family["english"] = "CGI abuses";
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
The source.jsp file, distributed with Apache Tomcat server, will
disclose information when passed a malformed request. As a result,
information such as the web root path and directory listings could
be obtained.

The following information was obtained via a malformed request to
the web server:");

port = get_http_port(default:80);

if(get_port_state(port))
 {
  pat1 = "Directory Listing";
  pat2 = "file";

  fl[0] = "/examples/jsp/source.jsp??";
  fl[1] = "/examples/jsp/source.jsp?/jsp/";

  for(i=0;fl[i];i=i+1) {
    req = http_get(item:fl[i], port:port);
    buf = http_keepalive_send_recv(port:port, data:req);
    if ( buf == NULL ) exit(0);
    if ( pat1 >< buf && pat2 >< buf) {
     warning += string("\n", buf);
     warning += string("\nSolution: Remove default files from the web server");
     warning += string("\nSee also: http://www.securityfocus.com/bid/4876");
     warning += string("\nRisk factor : Medium");
	security_warning(port:port, data:warning);
	exit(0);
     }
    }
}

