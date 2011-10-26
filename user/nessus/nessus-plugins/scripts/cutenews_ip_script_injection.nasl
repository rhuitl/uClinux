#
# (C) Tenable Network Security
#


if (description) {
  script_id(17256);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-0645");
  script_bugtraq_id(12691, 14328);
 
  name["english"] = "CuteNews <= 1.3.6 Multiple Vulnerabilities";
  script_name(english:name["english"]);

  desc["english"] = "
Synopsis :

The remote web server contains several PHP scripts that are prone to
multiple flaws, including possible arbitrary PHP code execution.

Description :

According to its version number, the remote host is running a version
of CuteNews that allows an attacker to inject arbitrary script through
the variables 'X-FORWARDED-FOR' or 'CLIENT-IP' when adding a comment. 
On one hand, an attacker can inject a client-side script to be
executed by an administrator's browser when he/she chooses to edit the
added comment.  On the other, an attacker with local access could
leverage this flaw to run arbitrary PHP code in the context of the web
server user. 

Additionally, it suffers from a cross-site scripting flaw involving
the 'search.php' script.

See also : 

http://www.kernelpanik.org/docs/kernelpanik/cutenews.txt
http://retrogod.altervista.org/cutenews.html

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:L/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for multiple vulnerabilities in CuteNews <= 1.3.6";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_require_ports("Services/www", 80);
  script_dependencies("cutenews_detect.nasl");

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # 1.3.6 is known to be affected; previous versions likely are too.
  if (ver =~ "^(0.*|1\.([0-2].*|3[^.]?|3\.[0-6]))") {
    security_warning(port);
    exit(0);
  }
}
