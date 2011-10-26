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
 script_id(10848);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2002-0563");
 script_bugtraq_id(4293);
 script_xref(name:"OSVDB", value:"705");

 name["english"] = "Oracle 9iAS Dynamic Monitoring Services";
 name["francais"] = "Oracle 9iAS Dynamic Monitoring Services";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
In a default installation of Oracle 9iAS, it is possible to access the 
Dynamic Monitoring Services pages anonymously. Access to these pages 
should be restricted.

Solution: 
Edit httpd.conf to restrict access to /dms0.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for presence of Oracle9iAS Dynamic Monitoring Services";
 
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
 req = http_get(item:"/dms0", port:port);	      
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("DMSDUMP version" >< r)	
 	security_hole(port);

 }
}
