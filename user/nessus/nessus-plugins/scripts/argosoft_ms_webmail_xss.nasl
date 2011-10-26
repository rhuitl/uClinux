#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server is affected by a cross-site scripting flaw. 

Description :

The remote host is running ArGoSoft Mail Server Pro, a messaging
system for Windows. 

According to its banner, the webmail server bundled with the version
of ArGoSoft Mail Server Pro installed on the remote host fails to
properly filter message headers before displaying them as part of a
message to users.  A remote attacker may be able to exploit this issue
to inject arbitrary HTML and script code into a user's browser, to be
executed within the security context of the affected web site. 

See also : 

http://secunia.com/secunia_research/2006-6/advisory/
http://www.argosoft.com/rootpages/MailServer/ChangeList.aspx

Solution :

Upgrade to ArGoSoft Mail Server Pro version 1.8.8.6 or later. 

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";


if (description) {
  script_id(20985);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0978");
  script_bugtraq_id(16834);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"23512");
  }

  script_name(english:"ArGoSoft Mail Server Pro Webmail Server Cross-Site Scripting Vulnerabilities");
  script_summary(english:"Checks version of ArGoSoft Mail Server Pro banner");

  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Check the banner.
banner = get_http_banner(port:port);
if (
  banner && 
  egrep(pattern:"^Server: ArGoSoft Mail Server Pro.+ \((0\.|1\.([0-7]\.|8\.([0-7]|8\.[0-5])))", string:banner)
) {
  security_note(port);
}
