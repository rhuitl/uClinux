#
# (C) Tenable Network Security
#


if (description) {
  script_id(18188);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2004-1570", "CVE-2004-1865", "CVE-2005-1309", "CVE-2005-1310");
  script_bugtraq_id(13397, 13398);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15754");
    script_xref(name:"OSVDB", value:"15755");
    script_xref(name:"OSVDB", value:"15756");
  }

  name["english"] = "bBlog <= 0.7.4 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote host contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running bBlog, an open-source blog software
application.

According to its banner, the remote version of this software suffers
from several vulnerabilities:

  o A SQL Injection Vulnerability
    It is reportedly possible to inject SQL statements through
    the 'postid' parameter of the 'index.php' script.

  o Multiple Cross-Site Scripting Vulnerabilities
    The application fails to properly sanitize user-supplied
    input through the blog entry title field and the comment 
    body text.

See also :

http://www.nessus.org/u?6f0a35ed

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in bBlog <= 0.7.4";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
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


# Search for bBlog.
foreach dir (cgi_dirs()) {
  # Grab the admin index.php -- by default it holds the version number.
  req = http_get(item:string(dir, "/bblog/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it's bBlog...
  if ("Welcome to bBlog" >< res || "<h1>bBlog</h1>" >< res) {
    if (egrep(string:res, pattern:"^bBlog \.([0-6].+|7\.[0-4])</a> &copy; 200")) {
      security_warning(port);
      exit(0);
    }
  }
}
