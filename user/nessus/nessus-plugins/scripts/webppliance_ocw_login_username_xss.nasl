#
# (C) Tenable Network Security
#


if (description) {
  script_id(19781);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-3014");
  script_bugtraq_id(14836);

  name["english"] = "WEBppliance ocw_login_username Parameter Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote host contains a PHP script that is vulnerable to cross-site
scripting attacks. 

Description :

The remote host is running WEBppliance, a web hosting control panel
for Windows and Linux from Ensim. 

The installed version of WEBppliance is prone to cross-site scripting
attacks because it fails to sanitize user-supplied input to the
'ocw_login_username' parameter of the login script before using it in
dynamically generated webpages. 

See also : 

http://membres.lycos.fr/newnst/exploit/Ensim_Autentification_XSS_By_ConcorDHacK.html

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for ocw_login_username parameter cross-site scripting vulnerability in WEBppliance";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 19638);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:19638);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '")</script>';
exss = urlencode(str:xss);


# Make sure the affected script exists.
req = http_get(item:"/webhost", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# If it looks like WEBppliance...
if (
  "Appliance Administrator Login" >< res &&
  "<INPUT type=text name=ocw_login_username" >< res
) {
  # Try to exploit the flaw.
  postdata = string(
    'ocw_login_username=">', exss, "&",
    "ocw_login_password=nessus"
  );
  req = string(
    "POST /webhost HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
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
