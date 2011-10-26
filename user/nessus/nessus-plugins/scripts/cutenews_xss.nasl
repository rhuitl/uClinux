#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# Ref: Debasis Mohanty
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14318);
 script_bugtraq_id(10948);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"8833");
 }
 script_version ("$Revision: 1.12 $");
 
 name["english"] = "CuteNews XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis : 

The remote web server contains a PHP script that is prone to cross-site
scripting attacks.

Description : 

According to it's banner, the version of CuteNews on the remote host
fails to sanitize input to the 'archive' parameter of the
'show_archives.php' script.  An attacker, exploiting this flaw, would
need to be able to coerce a user to browse to a purposefully malicious
URI.  Upon successful exploitation, the attacker would be able to run
code within the web-browser in the security context of the CuteNews
server. 

See also :

http://secunia.com/advisories/12260/

Solution : 

Upgrade to CuteNews v1.3.2 or newer.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of show_archives.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);
 script_dependencie("cutenews_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);
if(!can_host_php(port:port)) 
	exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  loc = matches[2];
  req = http_get(item:string(loc, "/show_archives.php?archive=<script>foo</script>&subaction=list-archive&"),
 		port:port);			
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if( r == NULL ) exit(0);
  if("<script>foo</script>" >< r)
  {
    security_note(port);
    exit(0);
  }
}
