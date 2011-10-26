#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: phpMyAdmin team
#
#  This script is released under the GNU GPL v2

if(description)
{
 script_id(15478);
 script_cve_id("CVE-2004-2630");
 script_bugtraq_id(11391);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"10715");
 }
 
 script_version("$Revision: 1.8 $");
 name["english"] = "phpMyAdmin remote command execution";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis : 

The remote web server contains a PHP application that may allow
arbitrary command execution. 

Description :

According to its banner, the remote version of phpMyAdmin is vulnerable
to an unspecified vulnerability in the MIME-based transformation system
with 'external' transformations that may allow arbitrary command
execution.  Successful exploitation requires that PHP's 'safe_mode' be
enabled. 

See also :

http://secunia.com/advisories/12813/

Solution : 

Upgrade to phpMyAdmin version 2.6.0-pl2 or later.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of phpMyAdmin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("phpMyAdmin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if (!can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if ( ereg(pattern:"(2\.[0-5]\..*|2\.6\.0$|2\.6\.0-pl1)", string:ver) ) security_warning(port);
}
