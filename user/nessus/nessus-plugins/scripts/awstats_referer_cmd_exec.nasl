#
# (C) Tenable Network Security
#


if (description) {
  script_id(19415);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-1527");
  script_bugtraq_id(14525);

  name["english"] = "AWStats Referrer Arbitrary Command Execution Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a CGI script that allows execution of
arbitrary commands. 

Description :

The remote host is running AWStats, a free logfile analysis tool for
analyzing ftp, mail, web, ...  traffic. 

The version of AWStats installed on the remote host collects data
about the web referrers and uses them without proper sanitation in an
eval() statement.  Using specially-crafted referrer data, an attacker
can cause arbitrary Perl code to be executed on the remote host within
the context of the affected application once the stats page has been
regenerated and when a user visits the referer statistics page. 

Note that successful exploitation requires that at least one URLPlugin
be enabled. 

See also : 

http://www.idefense.com/application/poi/display?id=290
http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0239.html
http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0371.html

Solution : 

Upgrade to AWStats 6.5 or later.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for referrer arbitrary command execution vulnerability in AWStats";
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


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to call the affected script.
  req = http_get(item:string(dir, "/awstats.pl"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # Try to pull the version number from a meta tag.
  pat = '<meta name="generator" content="AWStats (.+) from';
  matches = egrep(string:res, pattern:pat);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(string:match, pattern:pat);
      if (ver == NULL) break;
      ver = ver[1];
      break;
    }
  }

  # If that failed, try the banner.
  if (isnull(ver)) {
    pat = "<b>Advanced Web Statistics (.+)</b> - <a href=";
    matches = egrep(string:res, pattern:pat);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(string:match, pattern:pat);
        if (ver == NULL) break;
        ver = ver[1];
        break;
      }
    }
  }

  # Check the version number.
  if (ver && ver =~ "^([0-5]\.|6\.[0-4]^[0-9]?)") {
    security_warning(port);
    exit(0);
  }
}
