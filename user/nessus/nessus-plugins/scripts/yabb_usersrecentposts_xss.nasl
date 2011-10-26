#
# (C) Tenable Network Security
#


if (description) {
  script_id(17305);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-0741", "CVE-2005-0785");
  script_bugtraq_id(12756);

  name["english"] = "YaBB usersrecentposts Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a CGI application that is prone to 
cross-site scripting attacks.

Description :

The installed version of YaBB (Yet Another Bulletin Board) on the
remote host suffers from a remote cross-site scripting flaw due to its
failure to properly sanitize input passed via the 'username' parameter
and used as part of the 'usersrecentposts' action.  By exploiting this
flaw, a remote attacker can cause arbitrary code to be executed in a
user's browser in the context of the affected web site, resulting in
the theft of authentication data or other such attacks. 

Solution : 

Upgrade to YaBB version 2 RC2 or greater.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for usersrecentposts cross-site scripting vulnerability in YaBB";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

if (get_kb_item("www/"+port+"/generic_xss")) exit(0);
if (get_kb_item("www/no404/"+port)) exit(0);


if (thorough_tests) dirs = make_list("/yabb", "/yabb2", "/forum", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit it with an alert saying "Nessus-was-here".
  exploit = "<IFRAME%20SRC%3Djavascript:alert('Nessus%2Dwas%2Dhere')><%252FIFRAME>";
  req = http_get(
    item:string(
      dir, "/YaBB.pl?",
      "action=usersrecentposts;username=", exploit
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  # If we see the magic phrase, it's a problem.
  if ("<IFRAME SRC=javascript:alert('Nessus%2Dwas%2Dhere')" >< res) {
    security_note(port); 
    exit(0);
  }
}
