#
# (C) Tenable Network Security
#


if (description) {
  script_id(19940);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3163");
  script_bugtraq_id(14970);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"19693");
  }

  name["english"] = "Polipo Local Web Root Restriction Bypass Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server may expose files outside the local web root. 

Description :

The remote host is running the Polipo caching web proxy.  In addition to
caching web pages, the software also functions as a web server for
providing access to documentation, cached pages, etc. 

The built-in web server in the installed version of Polipo fails to
filter directory traversal sequences from requests.  By exploiting this
issue, an attacker may be able to retrieve files located outside the
local web root, subject to the privileges of the userid under which
Polipo runs. 

See also : 

http://sourceforge.net/mailarchive/forum.php?thread_id=6845581&forum_id=36515
http://www.pps.jussieu.fr/~jch/software/polipo/CHANGES.text

Solution :

Upgrade to Polipo 0.9.9 or later.

Risk factor :

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:C/A:N/I:N/B:C)";

  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for local web root restriction bypass vulnerability in Polipo";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("find_service.nes");
  script_require_ports("Services/www", 8123);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:8123);
if (!get_port_state(port)) exit(0);


# Make sure the banner indicates it's Polipo.
banner = get_http_banner(port:port);
if (banner && "Polipo" >< banner) {
  # Flag it as a proxy too.
  register_service(port:port, ipproto:"tcp", proto:"http_proxy");

  # Try to exploit the flaw.
  url = string("/../", SCRIPT_NAME, "/", rand_str());
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if the error suggests our request was unfiltered.
  if (egrep(string:res, pattern:string("The proxy on .+ error while fetching <strong>", url))) {
    security_warning(port);
    exit(0);
  }
}

