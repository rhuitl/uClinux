#
# (C) Tenable Network Security
#


if (description) {
  script_id(20241);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3754", "CVE-2005-3755", "CVE-2005-3756", "CVE-2005-3757", "CVE-2005-3758");
  script_bugtraq_id(15509);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"20977");
    script_xref(name:"OSVDB", value:"20978");
    script_xref(name:"OSVDB", value:"20979");
    script_xref(name:"OSVDB", value:"20980");
    script_xref(name:"OSVDB", value:"20981");
  }

  script_name(english:"Google Search Appliance proxystylesheet Parameter Multiple Vulnerabilities");
  script_summary(english:"Checks for proxystylesheet parameter multiple vulnerabilities in Google Search Appliance");
 
  desc = "
Synopsis :

The remote web server is affected by multiple flaws. 

Description :

The remote Google Search Appliance / Mini Search Appliance fails to
sanitize user-supplied input to the 'proxystylesheet' parameter, which
is used for customization of the search interface.  Exploitation of
this issue may lead to arbitrary code execution (as an unprivileged
user), port scanning, file discovery, and cross-site scripting. 

See also :

http://metasploit.com/research/vulns/google_proxystylesheet/
http://lists.grok.org.uk/pipermail/full-disclosure/2005-November/038940.html

Solution :

Contact Google for a fix. 

Risk factor :

Medium / CVSS Base Score : 4.8
(AV:L/AC:L/Au:NR/C:P/I:P/A:P/B:I)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("google_search_appliance_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!get_kb_item(string("www/", port, "/google_search_appliance"))) exit(0);


file = "../../../../../../../../../../etc/passwd";
req = http_get(
  item:string(
    "/search?",
    "site=nessus&",
    "output=xml_no_dtd&",
    "q=", SCRIPT_NAME, "&",
    "proxystylesheet=", file
  ), 
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if the error message indicates...
if (
  # the file doesn't exist or...
  string("ERROR: Unable to fetch the stylesheet from source: ", file) >< res ||
  # the file does exist but isn't a valid stylesheet.
  "The following required pattern was not found:" >< res
) {
  security_warning(port);
  exit(0);
}
