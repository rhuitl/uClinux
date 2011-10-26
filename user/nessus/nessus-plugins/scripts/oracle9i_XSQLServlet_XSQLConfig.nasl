#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10855);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2002-0568");
 script_bugtraq_id(4290);
 script_xref(name:"IAVA", value:"2002-t-0006");
 script_xref(name:"OSVDB", value:"3423");

 name["english"] = "Oracle XSQLServlet XSQLConfig.xml File";
 name["francais"] = "Oracle XSQLServlet XSQLConfig.xml File";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to read the contents of the XSQLConfig.xml file which contains 
sensitive information.

Solution: 
Move this file to a safer location and update your servlet engine's 
configuration file to reflect the change.

References:
http://www.nextgenss.com/papers/hpoas.pdf (Hackproofing Oracle9iAS)
http://www.oracle.com/

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for presence of XSQLConfig.xml";
 
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
 req = http_get(item:"/xsql/lib/XSQLConfig.xml",
 		port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 tip = string("On a PRODUCTION system, under no circumstances should this confi
guration file reside in a directory that is browseable through the virtual path
 of your web server.");

if(tip >< r)
 {
 http_close_socket(soc);
 security_hole(port);
 }
else
 {
 req = http_get(item:"/servlet/oracle.xml.xsql.XSQLServlet/xsql/lib/XSQLConfig.xml", port:port);
 soc = http_open_socket(port);
 if(soc)
  {
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if(tip >< r)	
 	security_hole(port);

   }
  }
 }
}
