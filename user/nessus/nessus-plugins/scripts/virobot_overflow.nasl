#
# (C) Tenable Network Security
#


if (description) {
  script_id(18494);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2041");
  script_bugtraq_id(13964);
  script_xref(name:"OSVDB", value:"17320");

  name["english"] = "ViRobot Linux Server Remote Buffer Overflow Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote server is prone to a remote buffer overflow attack. 

Description :

The remote host is running ViRobot Linux Server, a commercial anti-
virus product for Linux. 

According to its banner, the installed version of ViRobot Linux Server
suffers from a remote buffer overflow vulnerability in its web-based
management interface.  By passing specially-crafted data through the
'ViRobot_ID' and 'ViRobot_PASS' cookies when calling the 'addschup'
CGI script, an unauthenticated attacker may be able to write arbitrary
data to root's crontab entry, thus giving him complete control over
the affected host. 

See also : 

http://www.digitalmunition.com/DMA%5B2005-0614a%5D.txt
http://archives.neohapsis.com/archives/fulldisclosure/2005-06/0188.html
http://www.globalhauri.com/html/download/down_unixpatch.html

Solution : 

Unknown at this time.

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for remote buffer overflow vulnerability in ViRobot Linux Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);


# For each CGI directory...
foreach dir (cgi_dirs()) {
  # Make sure the affected script exists.
  req = http_get(item:string(dir, "/addschup"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(1);

  # If it looks like the script.
  if ("<font size=2>You need to authenticate.</font>" >< res) {
    # Get the site's index.html -- it has the version number in its title.
    req = http_get(item:"/index.html", port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(1);

    # There's a problem if the version number is <= 2.0.
    if (
      egrep(
        string:res, 
        pattern:"<title>ViRobot Linux Server Ver ([01]\..*|2\.0)</title>"
      )
    ) {
      security_hole(port);
      exit(0);
    }
  }
}
