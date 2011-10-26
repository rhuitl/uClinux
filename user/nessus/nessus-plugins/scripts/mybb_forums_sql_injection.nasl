#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is susceptible to SQL
injection attacks. 

Description :

The remote version of MyBB fails to sanitize input to the 'forums'
parameter of the 'search.php' script before using it in database
queries.  This may allow an unauthenticated attacker to uncover
sensitive information such as password hashes, modify data, launch
attacks against the underlying database, etc. 

See also :

http://www.securityfocus.com/archive/1/426631/30/30/threaded

Solution :

Edit 'search.php' and ensure 'forum' takes on only integer values as
described in the original advisory. 

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";


if (description) {
  script_id(21052);
  script_version("$Revision: 1.3 $");

  script_name(english:"MyBB forums Parameter SQL Injection Vulnerability");
  script_summary(english:"Checks for forums parameter SQL injection vulnerability in MyBB");
 
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

  # First we need a username.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  pat = '<a href="member.php\\?action=profile&amp;uid=[^>]+>([^<]+)</a>';
  matches = egrep(pattern:pat, string:res);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      user = eregmatch(pattern:pat, string:match);
      if (!isnull(user)) {
        user = user[1];
        break;
      }
    }
  }

  # If we have a username...
  if (user) {
    # Try to exploit the flaw to generate a SQL syntax error.
    req = http_get(
      item:string(
        dir, "/search.php?",
        "action=do_search&",
        "postthread=1&",
        "author=", user, "&",
        "matchusername=1&",
        "forums[]=-1'", SCRIPT_NAME
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see a syntax error with our script name.
    if (egrep(pattern:string("mySQL error: 1064.+near '", SCRIPT_NAME, ",'.+Query: SELECT f\\.fid"), string:res)) {
      security_warning(port);
      exit(0);
    }
  }
  else {
    #if (log_verbosity > 1) debug_print("couldn't find a username to use!", level:0);
  }
}
