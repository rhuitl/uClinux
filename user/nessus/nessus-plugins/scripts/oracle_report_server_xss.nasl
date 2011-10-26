#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17614);
 script_cve_id("CVE-2005-0873");
 script_bugtraq_id(12892);
 script_version("$Revision: 1.4 $");
 name["english"] = "Oracle Report Server XSS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Oracle Report Server, a reporting application.

The remote version of this software is vulnerable to a cross site scripting
vulnerability which may allow an attacker to use the remote host to
perform a cross site scripting attack.

Solution : Disable acccess to the file 'reports/Tools/test.jsp'
Risk factor: Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for a XSS in Oracle Reporting Server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(get_port_state(port))
{ 
 req = http_get(item:"/reports/examples/Tools/test.jsp?repprod<script>foo</script>", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( res == NULL ) exit(0);
 if( ' repprod<script>foo</script> ' >< res )	
 	security_warning(port);
}
