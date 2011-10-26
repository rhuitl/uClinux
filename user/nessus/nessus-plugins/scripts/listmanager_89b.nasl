#
# (C) Tenable Network Security
#


if (description) {
  script_id(20294);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-4143", "CVE-2005-4144", "CVE-2005-4146", "CVE-2005-4147", "CVE-2005-4148");
  script_bugtraq_id(15787, 15788);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"21548");
    script_xref(name:"OSVDB", value:"21549");
    script_xref(name:"OSVDB", value:"21550");
    script_xref(name:"OSVDB", value:"21551");
    script_xref(name:"OSVDB", value:"21573");
  }

  script_name(english:"ListManager < 8.9b Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in ListManager < 8.9b");
 
  desc = "
Synopsis :

The remote web server is vulnerable to multiple flaws. 

Description :

The remote host appears to be running ListManager, a web-based
commercial mailing list management application from Lyris. 

The version of ListManager installed on the remote host is affected by
a number of input validation flaws.  An unauthenticated attacker may
be able to exploit these issues to launch SQL injection attacks
against the backend database, view the source of any 'tml' script
available to the application, bypass authentication, or obtain
information about the server configuration. 

See also :

http://metasploit.com/research/vulns/lyris_listmanager/
http://archives.neohapsis.com/archives/fulldisclosure/2005-12/0349.html

Solution :

Upgrade to ListManager 8.9b or later.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

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
    egrep(pattern:"ListManagerWeb/([0-7]\.|8\.([0-8][^0-9]|9a))", string:banner) ||
    # earlier versions (eg, 8.5)
    (
      "Server: Tcl-Webserver" >< banner &&
      'Www-Authenticate: Basic realm="Lyris ListManager' >< banner
    )
  )
) security_warning(port);
