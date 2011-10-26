#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(16162);
  script_version ("$Revision: 1.5 $");

  script_cve_id("CVE-2005-0378");
  script_bugtraq_id(12255);

  name["english"] = "Horde 3.0 XSS";
  script_name(english:name["english"]);

  desc["english"] = "
The target is running at least one instance of Horde version 3.0,
which suffers from two cross site scripting vulnerabilities.  
Through specially crafted GET requests to the remote host, an attacker 
can cause a third party user to unknowingly run arbitrary Javascript code.  
For more information, see :

  http://www.hyperdose.com/advisories/H2005-01.txt

Solution : Upgrade to Horde version 3.0.1 or later.
Risk factor : Low";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for XSS flaws in Horde 3.0";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 George A. Theall");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "horde_detect.nasl");

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
debug_print("searching for XSS flaws in Horde 3.0 on port ", port, ".");

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/horde"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    debug_print("checking version ", ver, " under ", dir, ".");

    if (ereg(pattern:"^3\.0$", string:ver)) {
      security_note(port);
      exit(0);
    }
  }
}
