#
# (C) Tenable Network Security
#


if (description) {
  script_id(20213);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-3680");
  script_bugtraq_id(15406);

  script_name(english:"XOOPS xoopsConfig Parameter Local File Inclusion Vulnerabilities");
  script_summary(english:"Checks for xoopsConfig parameter local file inclusion vulnerabilities in XOOPS");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple local file inclusion issues. 

Description :

The remote installation of XOOPS fails to sanitize user-supplied input
to the 'xoopsConfig[language]' parameter of several xoopseditor
scripts before using it in PHP 'include' functions.  An
unauthenticated attacker may be able to leverage these issues to read
arbitrary local files and even execute arbitrary PHP code, subject to
the privileges of the web server user id.  Successful exploitation
requires that PHP's 'register_globals' setting be enabled and possibly
that 'magic_quotes_gpc' be disabled. 

See also :

http://retrogod.altervista.org/xoops_xpl.html

Solution :

Disable PHP's 'register_globals' setting and enable its
'magic_quotes_gpc' setting. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("xoops_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  #
  # nb: header.php in XOOP's main directory is useful because it should
  #     always be present, returns a message if called directly, and its
  #     use doesn't depend on magic_quotes_gpc.
  file = "../../../../header";
  if (thorough_tests) editors = make_list("dhtmltextarea", "koivi", "textarea");
  else editors = make_list("textarea");

  foreach editor (editors) {
    req = http_get(
      item:string(
        dir, "/class/xoopseditor/", editor, "/editor_registry.php?",
        "xoopsConfig[language]=", file
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we get a message about "root path".
    if ("XOOPS root path not defined" >< res) {
      security_warning(port);
      exit(0);
    }
  }
}
