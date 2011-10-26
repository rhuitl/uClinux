#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14693);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0694", "CVE-2004-0745", "CVE-2004-0769");
 
 name["english"] = "Fedora Core 2 2004-295: lha";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-295 (lha).

LHA is an archiving and compression utility for LHarc format archives.
LHA is mostly used in the DOS world, but can be used under Linux to
extract DOS files from LHA archives.

Install the lha package if you need to extract DOS files from LHA archives.

Update Information:

Lukasz Wojtow discovered a stack-based buffer overflow in all versions
of lha up to and including version 1.14. A carefully created archive could
allow an attacker to execute arbitrary code when a victim extracts or tests
the archive. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0769 to this issue.

Buffer overflows were discovered in the command line processing of all
versions of lha up to and including version 1.14. If a malicious user can
trick a victim into passing a specially crafted command line to the lha
command, it is possible that arbitrary code could be executed. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
names CVE-2004-0771 and CVE-2004-0694 to these issues.

Thomas Biege discovered a shell meta character command execution
vulnerability in all versions of lha up to and including 1.14. An attacker
could create a directory with shell meta characters in its name which could
lead to arbitrary command execution. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2004-0745 to
this issue.

Users of lha should update to this updated package


Solution : http://www.fedoranews.org/updates/FEDORA-2004-295.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lha package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"lha-1.14i-14.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lha-debuginfo-1.14i-14.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"lha-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0694", value:TRUE);
 set_kb_item(name:"CVE-2004-0745", value:TRUE);
 set_kb_item(name:"CVE-2004-0769", value:TRUE);
}
