#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(12262);
  script_version ("$Revision: 1.8 $");

  script_bugtraq_id(10667);
 
  name["english"] = "Open WebMail Content-Type XSS";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of Open WebMail whose
version is 2.32 or earlier.  Such versions are vulnerable to a cross
site scripting attack whereby an attacker can cause a victim to
unknowingly run arbitrary Javascript code by reading a MIME message
with a specially crafted Content-Type or Content-Description header. 
For further information, see :

  http://www.openwebmail.org/openwebmail/download/cert/advisories/SA-04:05.txt
  http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-2.txt
  http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-1.txt

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number of Open WebMail
***** installed there.

Solution : Upgrade to Open WebMail version 2.32 20040603 or later.

Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Content-Type XSS flaw in Open WebMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "openwebmail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (debug_level) display("debug: checking for Content-Type XSS flaw in Open WebMail on ", host, ":", port, ".\n");

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/openwebmail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    # nb: intermediate releases of 2.32 from 20040527 - 20040602 are 
    #     vulnerable, as are 2.32 and earlier releases.
    pat = "^(1\.|2\.([0-2]|3[01]|32$|32 20040(5|60[12])))";
    if (ereg(pattern:pat, string:ver)) {
      security_warning(port);
      exit(0);
    }
  }
}
