#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(16228);
  script_bugtraq_id(12337);
  script_version("$Revision: 1.5 $");

  script_cve_id(
    "CVE-2005-0075",
    "CVE-2005-0103", 
    "CVE-2005-0104"
  );
 
  name["english"] = "SquirrelMail < 1.4.4 XSS Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of SquirrelMail whose
version number suggests it is vulnerable to one or more cross-site
scripting vulnerabilities :

- Insufficient escaping of integer variables in webmail.php allows a
remote attacker to include HTML / script into a SquirrelMail webpage
(affects 1.4.0-RC1 - 1.4.4-RC1). 

- Insufficient checking of incoming URL vars in webmail.php allows an
attacker to include arbitrary remote web pages in the SquirrelMail
frameset (affects 1.4.0-RC1 - 1.4.4-RC1). 

- A recent change in prefs.php allows an attacker to provide a
specially crafted URL that could include local code into the
SquirrelMail code if and only if PHP's register_globals setting is
enabled (affects 1.4.3-RC1 - 1.4.4-RC1). 
 
***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number of Squirrelmail 
***** installed there.

Solution : Upgrade to SquirrelMail 1.4.4 or later.
Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Three XSS Vulnerabilities in SquirrelMail < 1.4.4";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 George A. Theall");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "squirrelmail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
debug_print("searching for 3 XSS vulnerabilities in SquirrelMail < 1.4.3 on port ", port, ".");


# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/squirrelmail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    debug_print("checking version ", ver, " under ", dir, ".");

    if (ereg(pattern:"^1\.4\.([0-3](-RC.*)?|4-RC1)$", string:ver)) {
      security_warning(port);
      exit(0);
    }
  }
}
