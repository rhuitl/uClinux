#
# (C) Tenable Network Security
#
# 

  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
numerous vulnerabilities. 

Description :

The remote host is running a version of UBB.threads that suffers from
multiple vulnerabilities due to insufficient input validation - local
file inclusion, HTTP response splitting, SQL injection, and cross-site
scripting.  These flaws may allow an attacker to completely compromise
the affected installation of UBB.threads. 

See also : 

http://www.securityfocus.com/archive/1/396222
http://www.gulftech.org/?node=research&article_id=00084-06232005

Solution : 

Upgrade to UBB.threads 6.5.2 beta or greater.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(18098);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-1199");
  script_bugtraq_id(13253, 14050, 14052, 14053, 14055);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15698");
  }

  name["english"] = "UBB.threads < 6.5.2 beta Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in UBB.threads < 6.5.2 beta";
  script_summary(english:summary["english"]);

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("ubbthreads_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/ubbthreads"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # 6.5.1.1 and below are vulnerable.
  if (safe_checks()) {
    if (ver =~ "^([0-5]\.|6\.([0-4][^0-9]|5$|5\.0|5\.1(\.1)?))") {
      report = string(
        desc["english"],
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Note that Nessus has determined the vulnerability exists on the\n",
        "remote host simply by looking at the version number of UBB.threads\n",
        "installed there."
      );

      security_warning(port:port, data:report);
    }
  }
  # Otherwise...
  else {
    # Get a list of existing boards on the target.
    req = http_get(item:string(dir, "/ubbthreads.php"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # Loop through a couple of forums...
    i = 0;
    pat = dir + '/postlist.php\\?.*Board=([^"&]+)">';
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    foreach match (split(matches)) {
      match = chomp(match);
      board = eregmatch(pattern:pat, string:match);
      if (isnull(board) || ++i > 5) break;

      # Try a simple exploit.
      board = board[1];
      req = http_get(
        item:string(
          dir, "/printthread.php?",
          "Board=", board, "&",
          "type=post&",
          # nb: this should just produce a syntax error.
          "main='", SCRIPT_NAME
        ), 
        port:port
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # There's a problem if we see a syntax error.
      if (egrep(string:res, pattern:string("SQL Error:.+ near '", SCRIPT_NAME, "'"), icase:TRUE)) {
        security_warning(port);
        exit(0);
      }
    }
  }
}
