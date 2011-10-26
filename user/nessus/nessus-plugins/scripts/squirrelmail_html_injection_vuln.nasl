#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from 
#
#  George A. Theall <theall@tifaware.com>
#  and
#  Tenable Network Security
#
# This script is released under the GNU GPLv2
#
#  Credit: SquirrelMail Team
# 
# modification by George A. Theall
# -change summary
# -remove references to global settings
# -clearer description
# -changed HTTP attack vector -> email


if (description) {
  script_id(14217);
  script_bugtraq_id(10450);
  script_cve_id("CVE-2004-0639");
  script_version ("$Revision: 1.11 $");

  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"8292");
  }


  name["english"] = "SquirrelMail From Email header HTML injection vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of SquirrelMail whose
version number is between 1.2.0 and 1.2.10 inclusive.  Such versions do
not properly sanitize From headers, leaving users vulnerable to XSS
attacks.  Further, since SquirrelMail displays From headers when listing
a folder, attacks does not require a user to actually open a message,
only view the folder listing.

For example, a remote attacker could effectively launch a DoS against
a user by sending a message with a From header such as :

From:<!--<>(-->John Doe<script>document.cookie='PHPSESSID=xxx; path=/';</script><>

which rewrites the session ID cookie and effectively logs the user
out.

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of Squirrelmail
***** installed there.

Solution : Upgrade to SquirrelMail 1.2.11 or later or wrap the call to
sqimap_find_displayable_name in printMessageInfo in
functions/mailbox_display.php with a call to htmlentities.

Risk factor : Medium";

  script_description(english:desc["english"]);
 
  summary["english"] = "Check Squirrelmail for HTML injection vulnerability";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencie("squirrelmail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) 
	exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/squirrelmail"));
if (isnull(installs)) 
	exit(0);

foreach install (installs) 
{
	matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  	if (!isnull(matches)) 
	{
    		ver = matches[1];
    		dir = matches[2];

    		if (ereg(pattern:"^1\.2\.([0-9]|10)$", string:ver)) 
		{
      			security_warning(port);
      			exit(0);
    		}
  	}
}


