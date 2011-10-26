#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19884);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-2871", "CVE-2005-2968");
 
 name["english"] = "Fedora Core 4 2005-963: thunderbird";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-963 (thunderbird).

Mozilla Thunderbird is a standalone mail and newsgroup client.

Update Information:

An updated thunderbird package that fixes various bugs is
now available for Fedora Core 4.

This update has been rated as having important security
impact by the Fedora Security Response Team.

Mozilla Thunderbird is a standalone mail and newsgroup client.

A bug was found in the way Thunderbird processes certain
international domain names. An attacker could create a
specially crafted HTML file, which when viewed by the victim
would cause Thunderbird to crash or possibly execute
arbitrary code. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-2871
to this issue.

A bug was found in the way Thunderbird processes certain
Unicode sequences. It may be possible to execute arbitrary
code as the user running Thunderbird if the user views a
specially crafted Unicode sequence. (CVE-2005-2702)

A bug was found in the way Thunderbird makes XMLHttp
requests. It is possible that a malicious web page could
leverage this flaw to exploit other proxy or server flaws
from the victim's machine. It is also possible that this
flaw could be leveraged to send XMLHttp requests to hosts
other than the originator; the default behavior of the
browser is to disallow this. (CVE-2005-2703)

A bug was found in the way Thunderbird implemented its XBL
interface. It may be possible for a malicious web page to
create an XBL binding in such a way that would allow
arbitrary JavaScript execution with chrome permissions.
Please note that in Thunderbird 1.0.6 this issue is not
directly exploitable and will need to leverage other unknown
exploits. (CVE-2005-2704)

An integer overflow bug was found in Thunderbird's
JavaScript engine. Under favorable conditions, it may be
possible for a malicious mail message to execute arbitrary
code as the user running Thunderbird. Please note that
JavaScript support is disabled by default in Thunderbird.
(CVE-2005-2705)

A bug was found in the way Thunderbird displays about:
pages. It is possible for a malicious web page to open an
about: page, such as about:mozilla, in such a way that it
becomes possible to execute JavaScript with chrome
privileges. (CVE-2005-2706)

A bug was found in the way Thunderbird opens new windows. It
is possible for a malicious web site to construct a new
window without any user interface components, such as the
address bar and the status bar. This window could then be
used to mislead the user for malicious purposes. (CVE-2005-2707)

A bug was found in the way Thunderbird processes URLs passed
to it on the command line. If a user passes a malformed URL
to Thunderbird, such as clicking on a link in an instant
messaging program, it is possible to execute arbitrary
commands as the user running Thunderbird. (CVE-2005-2968)

Users of Thunderbird are advised to upgrade to this updated
package that contains Thunderbird version 1.0.7 and is not
vulnerable to these issues.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the thunderbird package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"thunderbird-1.0.7-1.1.fc4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"thunderbird-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2702", value:TRUE);
 set_kb_item(name:"CVE-2005-2703", value:TRUE);
 set_kb_item(name:"CVE-2005-2704", value:TRUE);
 set_kb_item(name:"CVE-2005-2705", value:TRUE);
 set_kb_item(name:"CVE-2005-2706", value:TRUE);
 set_kb_item(name:"CVE-2005-2707", value:TRUE);
 set_kb_item(name:"CVE-2005-2871", value:TRUE);
 set_kb_item(name:"CVE-2005-2968", value:TRUE);
}
