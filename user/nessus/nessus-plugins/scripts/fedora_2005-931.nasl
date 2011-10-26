#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19876);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-2968");
 
 name["english"] = "Fedora Core 3 2005-931: firefox";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-931 (firefox).

Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance and portability.

Update Information:

An updated firefox package that fixes several security bugs
is now available for Fedora Core 3.

This update has been rated as having critical security
impact by the Fedora Security Response Team.

Mozilla Firefox is an open source Web browser.

A bug was found in the way Firefox processes XBM image
files. If a user views a specially crafted XBM file, it
becomes possible to execute arbitrary code as the user
running Firefox. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-2701
to this issue.

A bug was found in the way Firefox processes certain Unicode
sequences. It may be possible to execute arbitrary code as
the user running Firefox if the user views a specially
crafted Unicode sequence. (CVE-2005-2702)

A bug was found in the way Firefox makes XMLHttp requests.
It is possible that a malicious web page could leverage this
flaw to exploit other proxy or server flaws from the
victim's machine. It is also possible that this flaw could
be leveraged to send XMLHttp requests to hosts other than
the originator; the default behavior of the browser is to
disallow this. (CVE-2005-2703)

A bug was found in the way Firefox implemented its XBL
interface. It may be possible for a malicious web page to
create an XBL binding in such a way that would allow
arbitrary JavaScript execution with chrome permissions.
Please note that in Firefox 1.0.6 this issue is not directly
exploitable and will need to leverage other unknown
exploits. (CVE-2005-2704)

An integer overflow bug was found in Firefox's JavaScript
engine. Under favorable conditions, it may be possible for a
malicious web page to execute arbitrary code as the user
running Firefox. (CVE-2005-2705)

A bug was found in the way Firefox displays about: pages. It
is possible for a malicious web page to open an about: page,
such as about:mozilla, in such a way that it becomes
possible to execute JavaScript with chrome privileges.
(CVE-2005-2706)

A bug was found in the way Firefox opens new windows. It is
possible for a malicious web site to construct a new window
without any user interface components, such as the address
bar and the status bar. This window could then be used to
mislead the user for malicious purposes. (CVE-2005-2707)

A bug was found in the way Firefox processes URLs passed to
it on the command line. If a user passes a malformed URL to
Firefox, such as clicking on a link in an instant messaging
program, it is possible to execute arbitrary commands as the
user running Firefox. (CVE-2005-2968)

Users of Firefox are advised to upgrade to this updated
package that contains Firefox version 1.0.7 and is not
vulnerable to these issues.



Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the firefox package";
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
if ( rpm_check( reference:"firefox-1.0.7-1.1.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"firefox-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2701", value:TRUE);
 set_kb_item(name:"CVE-2005-2702", value:TRUE);
 set_kb_item(name:"CVE-2005-2703", value:TRUE);
 set_kb_item(name:"CVE-2005-2704", value:TRUE);
 set_kb_item(name:"CVE-2005-2705", value:TRUE);
 set_kb_item(name:"CVE-2005-2706", value:TRUE);
 set_kb_item(name:"CVE-2005-2707", value:TRUE);
 set_kb_item(name:"CVE-2005-2968", value:TRUE);
}
