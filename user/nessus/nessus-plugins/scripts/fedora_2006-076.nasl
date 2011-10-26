#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20848);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0296");
 
 name["english"] = "Fedora Core 4 2006-076: firefox";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-076 (firefox).

Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance and portability.

Update Information:

Mozilla Firefox is an open source Web browser.

Igor Bukanov discovered a bug in the way Firefox's
JavaScript interpreter dereferences objects. If a user
visits a malicious web page, Firefox could crash or execute
arbitrary code as the user running Firefox. The Common
Vulnerabilities and Exposures project assigned the name
CVE-2006-0292 to this issue.

moz_bug_r_a4 discovered a bug in Firefox's
XULDocument.persist() function. A malicious web page could
inject arbitrary RDF data into a user's localstore.rdf file,
which can cause Firefox to execute arbitrary JavaScript when
a user runs Firefox. (CVE-2006-0296)

A denial of service bug was found in the way Firefox saves
history information. If a user visits a web page with a very
long title, it is possible Firefox will crash or take a very
long time to start the next time it is run. (CVE-2005-4134)


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the firefox package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"firefox-1.0.7-1.2.fc4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"firefox-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-4134", value:TRUE);
 set_kb_item(name:"CVE-2006-0292", value:TRUE);
 set_kb_item(name:"CVE-2006-0296", value:TRUE);
}
