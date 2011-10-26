#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: vBulletin team
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(16203);
 script_bugtraq_id(12299);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "vBulletin Init.PHP unspecified vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by an
unspecified vulnerability. 

Description :

According to its banner, the remote version of vBulletin is vulnerable
to an unspecified issue.  It is reported that versions 3.0.0 through
to 3.0.4 are prone to a security flaw in 'includes/init.php'. 
Successful exploitation requires that PHP's 'register_globals' setting
be enabled. 

See also :

http://www.vbulletin.com/forum/showthread.php?t=125480

Solution : 

Upgrade to vBulletin 3.0.5 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of vBulletin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses";
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
  if ( ver =~ '^3.0(\\.[0-4])?[^0-9]' ) security_hole(port);
}
