#
# (C) Tenable Network Security
#


if (description) {
  script_id(19314);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-2430");
  script_bugtraq_id(14405);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"18299");
    script_xref(name:"OSVDB", value:"18300");
    script_xref(name:"OSVDB", value:"18301");
    script_xref(name:"OSVDB", value:"18302");
    script_xref(name:"OSVDB", value:"18303");
    script_xref(name:"OSVDB", value:"18304");
  }

  name["english"] = "Gforge <= 4.5 Multiple Cross-Site Scripting Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by
multiple cross-site scripting vulnerabilities. 

Description :

The remote host is running GForge, an open-source software development
collaborative toolset using PHP and PostgreSQL. 

The installed version of GForge on the remote host fails to properly
sanitize user-supplied input to several parameters / scripts before
using it in dynamically generated pages.  An attacker can exploit
these flaws to launch cross-site scripting attacks against the
affected application. 

See also : 

http://www.securityfocus.com/archive/1/406723/30/0/threaded

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple cross-site scripting vulnerabilities in Gforge <= 4.5";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '");</script>';


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit one of the flaws.
  req = http_get(
    item:string(
      dir, "/forum/forum.php?",
      "forum_id=", urlencode(str:string('">', xss))
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see our XSS as part of a PostgreSQL error.
  if (string('pg_atoi: error in "">', xss) >< res) {
    security_note(port);
    exit(0);
  }
}
