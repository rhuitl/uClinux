#
# (C) Tenable Network Security
#


if (description) {
  script_id(18446);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-1945", "CVE-2005-1946");
  script_bugtraq_id(13910);

  name["english"] = "Invision Community Blog Multiple Input Validation Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application is vulnerable to
multiple attacks. 

Description :

The remote host is running Invision Community Blog, a plugin for
Invision Power Board that lets users have their own blogs. 

The version installed on the remote host fails to properly sanitize
user-supplied data making it prone to multiple SQL injection and
cross-site scripting vulnerabilities.  These flaws may allow an
attacker to gain access to sensitive information such as passwords and
cookie data. 

See also : 

http://www.gulftech.org/?node=research&article_id=00078-06072005

Solution : 

Upgrade to Invision Community Blog 1.1.2 Final or greater.

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:L/Au:R/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple input validation vulnerabilities in Invision Community Blog";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("invision_power_board_detect.nasl");
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
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # To exploit it, we need to find an existing blog.
  req = http_get(item:string(dir, "/index.php?automodule=blog"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  pat = string(dir, "/index.php?s=.+&amp;automodule=blog&amp;blogid=([0-9]+)&amp;");
  matches = egrep(string:res, pattern:pat, icase:TRUE);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      blog = eregmatch(pattern:pat, string:match);
      if (!isnull(blog)) {
        blog = blog[1];

        # Try to exploit one of the SQL injection vulnerabilities.
        req = http_get(
          item:string(
            dir, "/index.php?",
            "automodule=blog&",
            "blog=", blog, "&",
            "cmd=editentry&",
            # nb: look for this exploit string later.
            "eid=99'", SCRIPT_NAME
          ),
          port:port
        );
        res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
        if (res == NULL) exit(0);

        if (
          "an error in your SQL syntax" >< res &&
          egrep(
            string:res, 
            pattern:string("SELECT \* FROM .*entries WHERE entry_id = 99&amp;#39;", SCRIPT_NAME)
          )
        ) {
          security_note(port);
          exit(0);
        }

        # We're not vulnerable, but we're finished checking too.
        break;
      }
    }
  }
}
