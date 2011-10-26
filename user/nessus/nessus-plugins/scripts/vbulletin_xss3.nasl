#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(16280);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"13150");
  
 script_version("$Revision: 1.4 $");
 name["english"] = "vBulletin BB Tag XSS";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is susceptible to a
cross-site scripting attack. 

Description :

According to its banner, the remote version of vBulletin is earlier
than 2.3.6 / 3.0.6.  Such versions are reportedly vulnerable to a
cross-site scripting issue involving its BB code parsing. 

As a result of this vulnerability, it is possible for a remote
attacker to create a malicious link containing script code that will
be executed in the browser of an unsuspecting user when followed. 

This may facilitate the theft of cookie-based authentication
credentials as well as other attacks. 

See also :

http://archives.neohapsis.com/archives/fulldisclosure/2005-01/0526.html
http://www.vbulletin.com/forum/showthread.php?postid=800224

Solution : 

Upgrade to vBulletin version 2.3.6 / 3.0.6 or later.

Risk factor : 

Low / CVSS Base Score : 1 
(AV:R/AC:H/Au:R/C:N/A:N/I:P/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks BBTag XSS flaw in vBulletin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("vbulletin_detect.nasl");
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
  
# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ '^([0-1]\\.|2\\.([0-2])?[^0-9]|2\\.3(\\.[0-5])?[^0-9]|3\\.0(\\.[0-5])?[^0-9])' ) security_note(port);
}
