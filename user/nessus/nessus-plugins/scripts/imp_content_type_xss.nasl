#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(12263);
  script_bugtraq_id(10501);
  script_version ("$Revision: 1.9 $");

  script_cve_id("CVE-2004-0584");
  if (defined_func("script_xref")) {
    script_xref(name:"GLSA", value:"GLSA-200406-11");
  }
 
  name["english"] = "IMP Content-Type XSS Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote server is running at least one instance of IMP whose version
number is between 2.0 and 3.2.3 inclusive.  Such versions are vulnerable
to a cross-scripting attack whereby an attacker may be able to cause a
victim to unknowingly run arbitrary Javascript code simply by reading a
MIME message with a specially crafted Content-Type header. 

For information about the vulnerability, including exploits, see :

  - http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-2.txt
  - http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-1.txt

Note : Nessus has determined the vulnerability exists on the target
simply by looking at the version number of IMP installed there; it has
not attempted to actually exploit the vulnerability. 

Solution : Upgrade to IMP version 3.2.4 or later.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Content-Type XSS Vulnerability in IMP";
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
if (debug_level) display("debug: searching for Content-Type XSS vulnerability in IMP on ", host, ":", port, ".\n");

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

    if (ereg(pattern:"^(2\.|3\.(0|1|2|2\.[1-3]))$", string:ver)) {
      security_hole(port);
      exit(0);
    }
  }
}
