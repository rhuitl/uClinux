#
# (C) Tenable Network Security
#


if (description) {
  script_id(19716);
  script_version ("$Revision: 1.6 $");

  script_bugtraq_id(14786);

  name["english"] = "MyBBB rating Parameter SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to SQL
injection attacks. 

Description :

The remote version of MyBB is prone to a SQL injection attack due to
its failure to sanitize user-supplied input to the 'rating' parameter
of the 'ratethread.php' script before using it in database queries. 

See also :

http://www.s4a.cc/forum/archive/index.php/t-3953.html

Solution :

Enable PHP's 'magic_quotes_gpc' setting. 

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:H/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for rating parameter SQL injection vulnerability in MyBB";
  script_summary(english:summary["english"]);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
  script_dependencies("mybb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mybb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # First we need a thread id.
  req = http_get(item:string(dir, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  pat = '<a href="showthread\\.php\\?tid=([0-9]+)&amp;action=lastpost';
  matches = egrep(pattern:pat, string:res);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      thread = eregmatch(pattern:pat, string:match);
      if (!isnull(thread)) {
        tid = thread[1];
        break;
      }
    }
  }

  # If we have a thread id.
  if (isnull(tid)) {
    if (log_verbosity > 1) debug_print("couldn't find a thread id to use!", level:0);
  }
  else {
    # Try to exploit the flaw.
    #
    # nb: the advisory uses a POST but the code allows for a GET,
    #     and that's quicker in a plugin.
    req = http_get(
      item:string(
        dir, "/ratethread.php?",
        "tid=", tid, "&",
        "rating=1'", SCRIPT_NAME
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see a syntax error with our script name.
    if (
      egrep(
        string:res,
        pattern:string("mySQL error: 1064<br>.+near '", SCRIPT_NAME, "' .+Query: UPDATE .*threads SET numratings")
      )
    ) {
      security_warning(port);
      exit(0);
    }
  }
}
