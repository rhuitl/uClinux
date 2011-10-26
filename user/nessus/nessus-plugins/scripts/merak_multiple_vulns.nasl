#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(14379);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2004-1719", "CVE-2004-1720", "CVE-2004-1721", "CVE-2004-1722");
  script_bugtraq_id(10966);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"9037");
    script_xref(name:"OSVDB", value:"9038");
    script_xref(name:"OSVDB", value:"9039");
    script_xref(name:"OSVDB", value:"9040");
    script_xref(name:"OSVDB", value:"9041");
    script_xref(name:"OSVDB", value:"9042");
    script_xref(name:"OSVDB", value:"9043");
    script_xref(name:"OSVDB", value:"9044");
    script_xref(name:"OSVDB", value:"9045");
  }

  name["english"] = "Multiple Vulnerabilities in Merak Webmail / IceWarp Web Mail";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of Merak Webmail / IceWarp
Web Mail 5.2.7 or less or Merak Mail Server 7.5.2 or less -
<http://www.MerakMailServer.com/>.  This product is subject to
multiple XSS, HTML and SQL injection, and PHP source code disclosure
vulnerabilities. 

Solution : Upgrade to Merak Webmail / IceWarp Web Mail 5.2.8 or
Merak Mail Server 7.5.2 or later.

Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Multiple Vulnerabilities in Merak Webmail / IceWarp Web Mail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "http_version.nasl");
  script_require_ports("Services/www", 4096);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
# nb: if webmail component installed, it's defaults to 4096;
#     if mail server, it's on 32000.
port = get_http_port(default:4096);
if (debug_level) display("debug: searching for multiple vulnerabilities in Merak WebMail / IceWarp Web Mail on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# nb: software is accessible through either "/mail" (default) or "/".
dirs = make_list("/mail", "");
foreach dir (dirs) {

  # Try to retrieve inc/function.php since it's accessible in vulnerable versions.
  url = string(dir, "/inc/function.php");
  if (debug_level) display("debug: checking ", url, "...\n");

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);           # can't connect
  if (debug_level) display("debug: res =>>", res, "<<\n");

  # Check the server signature as well as the content of the file retrieved.
  if (
    egrep(string:res, pattern:"^Server: IceWarp", icase:TRUE) &&
    egrep(string:res, pattern:"function getusersession", icase:TRUE)
  ) {
    security_warning(port:port);
    exit(0);
  }
}
