#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Cheng Peng Su
#
#  This script is released under the GNU GPL v2


if(description)
{
 script_id(14792);
 script_bugtraq_id(10602, 10612);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"7256");
 script_cve_id("CVE-2004-0620");
  
 script_version("$Revision: 1.7 $");
 name["english"] = "vBulletin XSS";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is susceptible to
cross-site scripting attacks. 

Description :

According to its banner, the remote version of vBulletin is vulnerable
to a cross-site scripting issue, due to a failure of the application
to properly sanitize user-supplied input. 

As a result of this vulnerability, it is possible for a remote
attacker to create a malicious link containing script code that will
be executed in the browser of an unsuspecting user when followed. 

This may facilitate the theft of cookie-based authentication
credentials as well as other attacks. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2004-06/0386.html

Solution : 

Upgrade to vBulletin 3.0.2 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of vBulletin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
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
  if ( ver =~ '^3.0(\\.[01])?[^0-9]' ) security_note(port);
}
