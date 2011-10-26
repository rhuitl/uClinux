#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#
 
if (description) {
  script_id(12253);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2004-0412");
  script_bugtraq_id(10412);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"6422");
    script_xref(name:"CLSA", value:"CLSA-2004:842");
    script_xref(name:"FLSA", value:"FEDORA-2004-1734");
    script_xref(name:"GLSA", value:"GLSA-200406-04");
    script_xref(name:"MDKSA", value:"MDKSA-2004:051");
  }
 
  name["english"] = "Mailman Password Retrieval";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running version of the Mailman mailing list software that
allows a list subscriber to retrieve the mailman password of any other
subscriber by means of a specially crafted mail message to the server. 
That is, a message sent to $listname-request@$target containing the
lines :

    password address=$victim
    password address=$subscriber

will return the password of both $victim and $subscriber for the list
$listname@$target. 

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number of Mailman installed
***** there.

Solution : Upgrade to Mailman version 2.1.5 or newer.
Risk factor : Medium";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for Mailman Password Retrieval Vulnerability";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2005 George A. Theall");

  family["english"] = "Misc.";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "http_version.nasl", "mailman_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
debug_print("checking for Mailman Password Retrieval vulnerability on port ", port, ".");

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/Mailman"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    debug_print("checking version ", ver, " under ", dir, ".");

    if (ereg(pattern:"^2\.1(b[2-6]|rc1|\.[1-4])", string:ver)) {
      security_warning(port);
      exit(0);
    }
  }
}
