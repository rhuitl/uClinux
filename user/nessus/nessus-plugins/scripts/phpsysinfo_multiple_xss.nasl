#
# (C) Tenable Network Security
#


if (description) {
  script_id(17610);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-0870");
  script_bugtraq_id(12887);

  script_name(english:"PHPSysInfo Multiple Cross-Site Scripting Vulnerabilities");
  desc["english"] = "
Synopsis :

The remote web server contains two PHP scripts that are prone to
cross-site scripting attacks. 

Description :

The remote host is running phpSysInfo, a PHP script which parses the /proc
entries on Linux systems and displays them in HTML.

The version of phpSysInfo installed on the remote host is affected by
multiple cross-site scripting vulnerabilities due to its failure to
sanitize user-input to the 'sensor_program' parameter of 'index.php' and
the 'text[language]', 'text[template]', and 'VERSION' parameters of
'system_footer.php'.  If PHP's 'register_globals' setting is enabled, a
remote attacker can exploit these flaws to have arbitrary script
rendered in the browser of a user in the context of the affected web
site. 

See also : 

http://www.securityfocus.com/archive/1/394086
http://sourceforge.net/project/shownotes.php?release_id=376350&group_id=15

Solution : 

Upgrade to phpSysInfo 2.5 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);

  script_summary(english:"Checks for multiple cross-site scripting vulnerabilities in PHPSysInfo");

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
exss = urlencode(str:xss);


# Loop through various directories.
foreach dir (cgi_dirs()) {
  # Try to exploit one of the XSS flaws.
  req = http_get(
    item:string(
      dir, "/index.php?",
      "sensor_program=", exss
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see our XSS.
  if (string("Error: ", xss, " is not currently supported") >< res) {
    security_note(port);
    exit(0);
  }
}
