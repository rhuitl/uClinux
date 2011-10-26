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
 script_id(10852);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0006");
 script_bugtraq_id(4034);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2002-0562");
 name["english"] = "Oracle 9iAS Jsp Source File Reading";
 name["francais"] = "Oracle 9iAS Jsp Source File Reading";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
In a default installation of Oracle 9iAS it is possible to read the source of 
JSP files. When a JSP is requested it is compiled 'on the fly' and the 
resulting HTML page is returned to the user. Oracle 9iAS uses a folder to hold 
the intermediate files during compilation. These files are created in the same 
folder in which the .JSP page resides. Hence, it is possible to access the 
.java and compiled .class files for a given JSP page.

Solution: 

Edit httpd.conf to disallow access to the _pages folder. 

References:
http://wwww.nextgenss.com/advisories/orajsa.txt
http://www.oracle.com

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Test for Oracle 9iAS JSP Source File Reading";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache"); 
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
# This plugin uses a demo jsp to test for this vulnerability. It would be 
# better to use the output of webmirror.nasl to find valid .jsp pages
# which could then be used in the test. In situations where the demo pages
# have been removed this plugin will false negative.
 
 req = http_get(item:"/demo/ojspext/events/index.jsp", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("This page has been accessed" >< r)	
	req = http_get(item:"/demo/ojspext/events/_pages/_demo/_ojspext/_events/_index.java", port:port);
	soc = http_open_socket(port);
	if(soc)
	{
	send(socket:soc, data:req);
	r = http_recv(socket:soc);
	http_close_socket(soc);
	
	if("import oracle.jsp.runtime.*" >< r)security_warning(port);
  }
 }
}
