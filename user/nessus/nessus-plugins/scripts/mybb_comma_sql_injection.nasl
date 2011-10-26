#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is susceptible
to SQL injection attacks. 

Description :

The remote version of MyBB fails to sanitize input to the 'comma'
parameter used by several scripts before using it in database queries. 
This may allow an unauthenticated attacker to uncover sensitive
information such as password hashes, modify data, launch attacks
against the underlying database, etc. 

Note that successful exploitation requires that PHP's
'register_globals' setting be enabled. 

See also :

http://www.securityfocus.com/archive/1/426653/30/30/threaded

Solution :

Disable PHP's 'register_globals' setting.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:H/Au:NR/C:P/A:N/I:P/B:N)";


if (description) {
  script_id(21053);
  script_version("$Revision: 1.1 $");

  script_name(english:"MyBB comma Parameter SQL Injection Vulnerability");
  script_summary(english:"Checks for comma parameter SQL injection vulnerability in MyBB");
 
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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mybb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to generate a SQL syntax error.
  req = http_get(item:string(dir, "/showteam.php"), port:port);
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Cookie: comma='", SCRIPT_NAME, "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see a syntax error with our script name.
  if (egrep(pattern:string("mySQL error: 1064.+near.+", SCRIPT_NAME, "'.+Query: SELECT u\\.\\*"), string:res)) {
    security_warning(port);
    exit(0);
  }
}
