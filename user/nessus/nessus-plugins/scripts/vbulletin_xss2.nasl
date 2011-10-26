#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Arab VieruZ <arabviersus@hotmail.com>
#
#  This script is released under the GNU GPL v2


if(description)
{
 script_id(14833);
 script_bugtraq_id(6226);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"3280");
  
 script_version("$Revision: 1.4 $");
 name["english"] = "vBulletin XSS(2)";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is susceptible to a
cross-site scripting attack. 

Description :

The remote version of vBulletin is vulnerable to a cross-site
scripting issue due to a failure of the application to properly
sanitize user-supplied URI input. 

As a result of this vulnerability, it is possible for a remote
attacker to create a malicious link containing script code that will
be executed in the browser of an unsuspecting user when followed. 

This may facilitate the theft of cookie-based authentication
credentials as well as other attacks. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2002-11/0276.html

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks memberlist.php XSS flaw in vBulletin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("cross_site_scripting.nasl", "vbulletin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);
  
# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  buf = http_get(item:dir + "/memberlist.php?s=23c37cf1af5d2ad05f49361b0407ad9e&what=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if("<script>foo</script>" >< r) security_note(port);
}
