#
# (C) Tenable Network Security
#


if (description) {
  script_id(19335);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2460", "CVE-2005-2461", "CVE-2005-2462", "CVE-2005-2463");
  script_bugtraq_id(14425);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"18395");
    script_xref(name:"OSVDB", value:"18396");
    script_xref(name:"OSVDB", value:"18397");
    script_xref(name:"OSVDB", value:"18398");
    script_xref(name:"OSVDB", value:"18399");
  }

  name["english"] = "Kayako LiveResponse Multiple Input Validation Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by a
variety of flaws. 

Description :

The remote host is running Kayako LiveResponse, a web-based live
support system. 

The installed version of Kayako LiveResponse on the remote host fails
to sanitize user-supplied input to many parameters / scripts, which
makes the application vulnerable to SQL injection and cross-site
scripting attacks.  In addition, the application embeds passwords in
plaintext as part of GET requests and will reveal its installation
directory in response to direct calls to several scripts. 

See also : 

http://www.gulftech.org/?node=research&article_id=00092-07302005
http://www.securityfocus.com/archive/1/406914

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 4.6
(AV:R/AC:L/Au:NR/C:P/I:P/A:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple input validation vulnerabilities in Kayako LiveResponse";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

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
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);


# A simple alert.
xss = "<script>alert(document.cookie);</script>";


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the XSS flaw.
  req = http_get(
    item:string(
      dir, 
      "/index.php?",
      "username=", urlencode(str:string('">', xss)), "&",
      "password=", SCRIPT_NAME
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see our XSS as part of the LiveResponse login form.
  if (string('input name=username type=text value="\">', xss) >< res) {
    security_warning(port);
    exit(0);
  }
}
