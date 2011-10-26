#
# (C) Tenable Network Security
#


if(description)
{
 script_id(15951);
 script_cve_id("CVE-2004-2509", "CVE-2004-2510");
 script_bugtraq_id(11900);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"12364");
  script_xref(name:"OSVDB", value:"12365");
  script_xref(name:"OSVDB", value:"12366");
  script_xref(name:"OSVDB", value:"12367");
 }
 script_version("$Revision: 1.8 $");
 name["english"] = "UBB.threads Cross Site Scripting Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to 
various cross-site scripting attacks.

Description :

There are various cross-site scripting issues in the remote version of
this software.  An attacker may exploit them to use the remote website
to inject arbitrary HTML and script code into a user's browser to be
executed within the security context of the affected web site. 

See also : 

http://archives.neohapsis.com/archives/fulldisclosure/2004-12/0239.html

Solution : 

Upgrade to UBB.Threads version 6.5.1 or later.

Risk factor : 

Low / CVSS Base Score : 3.5
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:I)";

 script_description(english:desc["english"]);
 
 summary["english"] = "XSS UBB.threads";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("cross_site_scripting.nasl", "ubbthreads_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);
if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/ubbthreads"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];
 res = http_keepalive_send_recv(port:port, data:http_get(item:dir + "/calendar.php?Cat=<script>foo</script>", port:port), bodyonly:1);
 if ( res == NULL ) exit(0);
 if ( "<script>foo</script>" >< res ) security_note(port);
}
