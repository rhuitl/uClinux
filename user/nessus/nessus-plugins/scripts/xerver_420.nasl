#
# (C) Tenable Network Security
#


if (description) {
  script_id(20062);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-3293", "CVE-2005-4774");
  script_bugtraq_id(15135);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"20075");
    script_xref(name:"OSVDB", value:"20076");
    script_xref(name:"OSVDB", value:"20077");
  }

  script_name(english:"Xerver < 4.20 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in Xerver < 4.20");
 
  desc = "
Synopsis :

The remote web server is affected by multiple flaws. 

Description :

The remote host is running Xerver, an open-source FTP and web server
written in Java. 

The installed version of Xerver on the remote host suffers from
several vulnerabilities that can be used by an attacker to reveal the
contents of directories as well as the source of scripts and HTML
pages.  In addition, it is prone to a generic cross-site scripting
flaw. 

Solution :

Upgrade to Xerver 4.20 or later.

Risk factor : 

Low / CVSS Base Score : 3.3
(AV:R/AC:L/Au:NR/C:N/I:C/A:N/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Unless we're paranoid, make sure the banner looks like Xerver.
if (report_paranoia < 2) {
  banner = get_http_banner(port:port);
  if (!banner || "Server: Xerver" >!< banner) exit(0);
}


# Get the initial page.
#
# nb: Xerver doesn't deal nicely with http_keepalive_send_recv() for 
#     some reason so we don't use it below.
res = http_get_cache(item:"/", port:port);
if (res == NULL) exit(0);


# If that's a directory listing...
if ("<TITLE>Directory Listing" >< res) {
  if (!get_kb_item("www/" + port + "/generic_xss")) {
    # Try to exploit the XSS flaw.
    xss = "<script>alert('" + SCRIPT_NAME + "')</script>";
    req = http_get(item:raw_string("/%00/", urlencode(str:xss), "/"), port:port);
    res = http_send_recv(port:port, data:req);
    if (res == NULL) exit(0);

    # There's a problem if we see our XSS.
    if (
      "<TITLE>Directory Listing" >< res && 
      xss >< res
    ) {
      security_note(port);
    }
  }
}
# Otherwise...
else {
  # Try to force a directory listing.
  req = http_get(item:"/%00/", port:port);
  res = http_send_recv(port:port, data:req);
  if (res == NULL) exit(0);

  # There's a problem if we now get a directory listing.
  if ("<TITLE>Directory Listing" >< res) {
    security_note(port);
  }
}
