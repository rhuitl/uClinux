#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(11815);
  script_version ("$Revision: 1.9 $");
 
  name["english"] = "IMP_MIME_Viewer_html class XSS vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote server is running at least one instance of IMP whose version
number is between 3.0 and 3.2.1 inclusive.  Such versions are vulnerable
to several cross-scripting attacks whereby an attacker can cause a
victim to unknowingly run arbitrary Javascript code simply by reading an
HTML message from the attacker. 

Announcements of the vulnerabilities can be found at :

  - http://marc.theaimsgroup.com/?l=imp&m=105940167329471&w=2
  - http://marc.theaimsgroup.com/?l=imp&m=105981180431599&w=2
  - http://marc.theaimsgroup.com/?l=imp&m=105990362513789&w=2

Note : Nessus has determined the vulnerability exists on the target
simply by looking at the version number of IMP installed there.  If the
installation has already been patched, consider this a false positive. 

Solution : Upgrade to IMP version 3.2.2 or later or apply patches found
in the announcements to imp/lib/MIME/Viewer/html.php. 

Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "IMP_MIME_Viewer_html class is vulnerable to XSS attacks";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2004 George A. Theall");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "imp_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for MIME_Viewer_html XSS vulnerability in IMP on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/imp"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    if (ereg(pattern:"^3\.(0|1|2|2\.1)$", string:ver)) {
      security_hole(port);
      exit(0);
    }
  }
}
