#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15618);
 script_cve_id("CVE-2004-2171");
 script_bugtraq_id(9496);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:3707);

 script_version("$Revision: 1.7 $");
 name["english"] = "Cross-Site Scripting in Cherokee Error Pages";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis : 

The remote web server is vulnerable to a cross-site scripting issue.

Description :

The remote host is running Cherokee - a fast and tiny web server.

Due to a lack of sanitization from the user input, 
The remote version of this software is vulnerable to cross-site
scripting attacks due to lack of sanitization in returned error pages.

Solution : 

Upgrade to Cherokee 0.4.8 or newer.

Risk factor : 

Risk factor :

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of Cherokee";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Cherokee/0\.([0-3]\.|4\.[0-7])[^0-9]", string:serv))
 {
   req = http_get(item:"/<script>foo</script>", port:port);
   res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
   if ( "<script>foo</script>" >!< res ) exit(0);

   if ( func_has_arg("security_note", "confidence") )
   	security_note(port:port, confidence:100);
   else
   	security_note(port);
 }
