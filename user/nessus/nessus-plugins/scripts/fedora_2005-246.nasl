#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19632);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0399", "CVE-2005-0401", "CVE-2005-0402");
 
 name["english"] = "Fedora Core 3 2005-246: firefox";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-246 (firefox).

Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance and portability.

Update Information:

A buffer overflow bug was found in the way Firefox processes GIF
images. It is possible for an attacker to create a specially crafted
GIF image, which when viewed by a victim will execute arbitrary code
as the victim. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0399 to this issue.
A bug was found in the way Firefox processes XUL content. If a
malicious
web page can trick a user into dragging an object, it is possible to
load malicious XUL content. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-0401 to this
issue.
A bug was found in the way Firefox bookmarks content to the sidebar.
If a user can be tricked into bookmarking a malicious web page into
the sidebar panel, that page could execute arbitrary programs. The
Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-0402 to this issue.
Users of Firefox are advised to upgrade to this updated package which
contains Firefox version 1.0.2 and is not vulnerable to these issues.

Additionally, there was a bug found in the way Firefox rendered some
fonts, notably the Tahoma font while italicized. This issue has been
filed as Bug 150041 (bugzilla.redhat.com). This updated package
contains a fix for this issue.


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
if ( rpm_check( reference:"firefox-1.0.2-1.3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"firefox-debuginfo-1.0.2-1.3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"firefox-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0399", value:TRUE);
 set_kb_item(name:"CVE-2005-0401", value:TRUE);
 set_kb_item(name:"CVE-2005-0402", value:TRUE);
}
