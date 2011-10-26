#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains several PHP scripts that are prone to a
variety of flaws, including remote code execution. 

Description :

The remote host is running a version of phpMyFAQ that suffers from
arbitrary code execution (if the server is Windows-based), SQL
injection and cross-site scripting attacks, and information
disclosure. 

See also : 

http://retrogod.altervista.org/phpmyfuck151.html

Solution : 

Upgrade to phpMyFAQ 1.5.2 or later.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(19778);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(14927, 14928, 14929, 14930);

  name["english"] = "phpMyFAQ < 1.5.2 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in phpMyFAQ < 1.5.2";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("phpmyfaq_detect.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpmyfaq"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Try to exploit one of the XSS flaws.
  #
  # nb: I know this is lame but there's no way to test the SQL
  #     injection flaw, the remote code execution flaws work only
  #     under Windows, and trying to read the tracking logs will
  #     only work if the site has seen activity recently.
  if (!get_kb_item("www/"+port+"/generic_xss")) {
    # A simple alert.
    xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
    exss = urlencode(str:xss);

    # Try to exploit the flaw.
    req = http_get(
      item:string(
        dir, "/admin/footer.php?",
        "PMF_CONF[version]=", exss
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

  # Check the version number in case register_globals is off or the 
  # web server itself is vulnerable to cross-site scripting attacks.
  if (ver =~ "^(0\.|1\.([0-4]\.|5\.[01]($|[^0-9])))") {
    desc = str_replace(
      string:desc["english"],
      find:"See also :",
      replace:string(
        "***** Nessus has determined the vulnerability exists on the remote\n",
        "***** host simply by looking at the version number of phpMyFAQ\n",
        "***** installed there.\n",
        "\n",
        "See also :"
      )
    );
    security_warning(port:port, data:desc);
    exit(0);
  }
}
