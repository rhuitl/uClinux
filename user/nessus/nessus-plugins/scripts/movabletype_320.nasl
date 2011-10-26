#
# (C) Tenable Network Security
#


if (description) {
  script_id(19776);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3101", "CVE-2005-3102", "CVE-2005-3103", "CVE-2005-3104");
  script_bugtraq_id(14910, 14911, 14912);

  name["english"] = "Movable Type < 3.2 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains CGI scripts that are prone to arbitrary
remote command execution, information disclosure, and cross-site
scripting attacks. 

Description :

The remote host is running Movable Type, a blog software written in
Perl. 

The installed version of Movable Type allows an attacker to enumerate
valid usernames because its password reset functionality returns
different errors depending on whether the supplied username exists;
allows privileged users to upload files with arbitrary extensions,
possibly outside the web server's document directory; and fails to
sanitize certain fields when creating new blog entries of malicious
HTML and script code before using them to generate dynamic web pages. 

Solution : 

Upgrade to Movable Type 3.2 or later and grant only trusted users the
ability to upload files via the administrative interface. 

Risk factor :

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:R/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Movable Type < 3.2";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Loop through CGI directories.
if (thorough_test) dirs = make_list("/mt", "/cgi-bin/mt", "/blog", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (cgi_dirs()) {
  # Try to find Movable Type.
  req = http_get(item:"/mt.cgi", port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # Do a banner check.
  if (
    '<div id="copyright">' >< res &&
    egrep(
      string:res, 
      pattern:"^<b>Version ([0-2]\..*|3\.[01].*)</b> Copyright &copy; .+ Six Apart"
    )
  ) {
    security_note(port);
    exit(0);
  }
}
