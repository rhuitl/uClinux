#
# (C) Tenable Network Security
#


if (description) {
  script_id(18573);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-1113", "CVE-2005-1114", "CVE-2005-1115", "CVE-2005-1116");
  script_bugtraq_id(13149, 13150, 13151, 13152, 13153);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15925");
    script_xref(name:"OSVDB", value:"15926");
    script_xref(name:"OSVDB", value:"15927");
    script_xref(name:"OSVDB", value:"15928");
    script_xref(name:"OSVDB", value:"15929");
    script_xref(name:"OSVDB", value:"15930");
  }

  name["english"] = "Multiple Cross-Site Scripting Vulnerabilities in phpBB2 Plus <= 1.52";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is vulnerable to
multiple cross-site scripting attacks. 

Description :

The remote host is running a version of phpBB2 Plus that suffers from
multiple cross-site scripting flaws due to a general failure of the
application and associated modules to sanitize user-supplied input. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-04/0190.html

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple cross-site scripting vulnerabilities in phpBB Plus <= 1.52";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  # nb: phpbb_detect.nasl should identify installs of phpBB2 Plus
  #     since it's just a modified distribution of phpBB.
  script_dependencies("phpbb_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);
if (!can_host_php(port:port)) exit(0);


# A simple alert to display the script name.
xss = "<script>JavaScript:alert('" + SCRIPT_NAME + "');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = "%3Cscript%3EJavaScript:alert('" + SCRIPT_NAME + "')%3B%3C%2Fscript%3E";


# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit one of the XSS flaws.
  req = http_get(
    item:string(
      dir, "/calendar_scheduler.php?",
      "d=", unixtime(), "&",
      "mode=&",
      "start=%22%3E", exss, "&",
      "sid=69bfdd7e0b7c9852d26077789afafa84"
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # it looks like phpBB2 Plus and...
    'Powered by <a href="http://www.phpbb2.de/" target="_phpbb">phpBB2 Plus' >< res &&
    # we see our exploit.
    xss >< res
  ) {
    security_note(port);
    exit(0);
  }
}
