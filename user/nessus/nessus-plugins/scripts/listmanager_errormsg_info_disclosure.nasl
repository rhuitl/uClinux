#
# (C) Tenable Network Security
#


if (description) {
  script_id(20295);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-4148", "CVE-2005-4149");
  script_bugtraq_id(15789);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"21552");
  }

  script_name(english:"ListManager Error Message Information Disclosure Vulnerability");
  script_summary(english:"Checks for error message information disclosure vulnerability in ListManager");
 
  desc = "
Synopsis :

The remote web server is vulnerable to an information disclosure
vulnerability. 

Description :

The remote host appears to be running ListManager, a web-based
commercial mailing list management application from Lyris. 

In response to a request for a non-existent page, the version of
ListManager on the remote host returns sensitive information such as
the installation path and software version as well as possibly SQL
queries, code blocks, or the entire CGI environment. 

See also :

http://metasploit.com/research/vulns/lyris_listmanager/
http://archives.neohapsis.com/archives/fulldisclosure/2005-12/0349.html

Solution :

Unknown at this time.

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Make sure it's ListManager, unless we're being paranoid.
banner = get_http_banner(port:port);
if (
  paranoia_level < 2 &&
  banner && 
  (
    # later versions of ListManager
    "ListManagerWeb/" >!< banner &&
    # earlier versions (eg, 8.5)
    "Server: Tcl-Webserver" >!< banner
  )
) exit(0);


# Try to exploit the flaw.
req = http_get(item:string("/read/rss?forum=", SCRIPT_NAME), port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if we see a bug report form.
if (egrep(pattern:'<INPUT TYPE="HIDDEN" NAME="(env|errorInfo|version)', string:res)) {
  security_note(port);
  exit(0);
}
