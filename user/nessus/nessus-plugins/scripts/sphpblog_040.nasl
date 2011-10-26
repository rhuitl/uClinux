#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple issues. 

Description :

The remote host is running Simple PHP Blog, a blog written in PHP. 

The version of Simple PHP Blog installed on the remote host allows
authenticated attackers to upload files containing arbitrary code to
be executed within the context of the web server userid.  In addition,
it likely lets anyone retrieve its configuration file as well as the
user list and to delete arbitrary files subject to the privileges of
the web server user id. 

See also : 

http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0885.html
http://www.ftusecurity.com/pub/sphpblog_vulns

Solution : 

Upgrade to Simple PHP Blog 0.4.5 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(19516);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-2733", "CVE-2005-2787");
  script_bugtraq_id(14667, 14681);

  name["english"] = "Simple PHP Blog <= 0.4.0 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Simple PHP Blog <= 0.4.0";
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
  # Determine if this is Simple PHP Blog.
  res = http_get_cache(item:string(dir, "/"), port:port);
  if (res == NULL) exit(0);

  # If it looks like it is...
  if (
    '<meta name="generator" content="Simple PHP Blog' >< res ||
    'alt="button_sphpblog.png"' >< res
  ) {
    # Try to get the version.
    pat = '<meta name="generator" content="Simple PHP Blog ([^"]+)"';
    matches = egrep(string:res, pattern:pat);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }
    }

    if (isnull(ver)) {
      pat = 'button_sphpblog\\.png" [^>]+="Powered by Simple PHP Blog ([^"]+)"';
      matches = egrep(string:res, pattern:pat);
      if (matches) {
        foreach match (split(matches)) {
          match = chomp(match);
          ver = eregmatch(pattern:pat, string:match);
          if (!isnull(ver)) {
            ver = ver[1];
            break;
          }
        }
      }
    }

    # Try to grab 'config.txt' - it holds the blog's title as its first field.
    pat = "<title>(.+)</title>";
    matches = egrep(string:res, pattern:pat);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          title = title[1];
          break;
        }
      }
    }

    # Check whether the title is stored as the first field of config.txt.
    if (!isnull(title)) {
      # Try to retrieve one of the sensitive files.
      req = http_get(item:string(dir, "/config.txt"), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # There's a problem if the first field is the title.
      if (egrep(string:res, pattern:string("^", title, "|"))) {
        security_hole(port);
        exit(0);
      }
    }

    # If that didn't work, check the version number.
    if (ver && ver =~ "^0\.([0-3]|4\.0)") {
      report = string(
        desc["english"],
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus has determined the vulnerability exists on the remote\n",
        "host simply by looking at the version number of Simple PHP\n",
        "Blog installed there.\n"
      );
      security_hole(port:port, data:report);
      exit(0);
    }
  }
}
