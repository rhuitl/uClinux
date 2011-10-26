#
# (C) Tenable Network Security
#


if (description) {
  script_id(20342);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-4199", "CVE-2005-4200");
  script_bugtraq_id(15793);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"21600");
    script_xref(name:"OSVDB", value:"21601");
  }

  script_name(english:"MyBB < 1.0 Multiple SQL Injection Vulnerabilities");
  script_summary(english:"Checks for multiple SQL injection vulnerabilities in MyBB < 1.0");
 
  desc = "
Synopsis :

The remote web server has a PHP application that is affected by
multiple SQL injection vulnerabilities. 

Description :

The installed version of MyBB fails to validate user input to several
parameters of the 'calendar.php', 'usercp.php', 'member.php', and
'showthread.php' scripts before using them in database queries.  An
attacker leverage this issues to manipulate those queries, which may
lead to disclosure of sensitive information, modification of data, or
attacks against the underlying database. 

Note that these flaws can be exploited even if PHP's
'register_globals' setting is disabled and its 'magic_quotes_gpc'
setting is enabled.  Also, some do not require that an attacker first
authenticate. 

See also : 

http://www.trapkit.de/advisories/TKADV2005-12-001.txt
http://lists.grok.org.uk/pipermail/full-disclosure/2005-December/040584.html
http://community.mybboard.net/showthread.php?tid=5184

Solution : 

Upgrade to MyBB 1.0 or later.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

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

  # Make sure one of the affected scripts exists.
  req = http_get(item:string(dir, "/calendar.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ('<form action="calendar.php" method=' >< res) {
    postdata = string(
      "month=11'", SCRIPT_NAME, "&",
      "day=11&",
      "year=2005&",
      "subject=NESSUS&",
      "description=Plugin+Check&",
      "action=do_addevent"
    );
    req = string(
      "POST ", dir, "/calendar.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # There's a problem if we get a syntax error involving our script name.
    if (egrep(pattern:string("an error in your SQL syntax.+ near '", SCRIPT_NAME), string:res)) {
      security_warning(port);
      exit(0);
    }
  }
}
