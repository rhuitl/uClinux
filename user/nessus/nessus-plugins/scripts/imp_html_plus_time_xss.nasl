#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(13857);
  script_version ("$Revision: 1.9 $");

  script_cve_id("CVE-2004-1443");
  script_bugtraq_id(10845);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"8293");
  }

  name["english"] = "IMP HTML+TIME XSS Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = 
"The remote server is running at least one instance of IMP whose version
number is 3.2.4 or lower.  Such versions are vulnerable to a
cross-scripting attack whereby an attacker may be able to inject
arbitrary content, including script, in a specially crafted MIME
message.  To have an effect, the victim must be using Internet Explorer
to access IMP and be using the inline MIME viewer for HTML messages. 

This vulnerability is a variation on the one reported here :

  - http://www.greymagic.com/security/advisories/gm005-mc/

Note : Nessus has determined the vulnerability exists on the target
simply by looking at the version number of IMP installed there, it has
not attempted to actually exploit the vulnerability. 

Solution : Upgrade to IMP version 3.2.5 or later.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for HTML+TIME Vulnerability in IMP";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

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
if (debug_level) display("debug: searching for HTML+TIME XSS vulnerability in IMP on ", host, ":", port, ".\n");

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

    if (ereg(pattern:"^(1\.|2\.|3\.(0|1|2|2\.[1-4]))$", string:ver)) {
      security_hole(port);
      exit(0);
    }
  }
}
