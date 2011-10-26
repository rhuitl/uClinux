#
# (C) Tenable Network Security
#


if (description) {
  script_id(20806);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2005-4142");
  script_bugtraq_id(15786);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"21547");
  }

  script_name(english:"ListManager Administrative Command Injection Vulnerability");
  script_summary(english:"Checks for administrative command injection vulnerability in ListManager");
 
  desc = "
Synopsis :

The remote web server is affected by an administrative command injection
flaw. 

Description :

The remote host appears to be running ListManager, a web-based
commercial mailing list management application from Lyris. 

According to its banner, the version of ListManager installed on the
remote host does not sufficiently sanitize input to the 'pw' parameter
when processing new subscription requests via the web.  Using a
specially-crafted request, an unauthenticated attacker may be able to
leverage this flaw to inject administrative commands into the affected
application. 

See also :

http://metasploit.com/research/vulns/lyris_listmanager/
http://archives.neohapsis.com/archives/fulldisclosure/2005-12/0349.html

Solution :

Upgrade to ListManager 8.95 or later.

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Do a banner check.
banner = get_http_banner(port:port);
if (
  banner && 
  (
    # later versions of ListManager.
    egrep(pattern:"ListManagerWeb/([0-7]\.|8\.([0-8]|9[abc]))", string:banner) ||
    # earlier versions (eg, 8.5)
    (
      "Server: Tcl-Webserver" >< banner &&
      'Www-Authenticate: Basic realm="Lyris ListManager' >< banner
    )
  )
) security_warning(port);
