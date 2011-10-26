#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20756);
 script_version ("$Revision: 1.2 $");
 script_bugtraq_id(16325);
 script_cve_id("CVE-2006-0019");
 
 name["english"] = "Fedora Core 4 2006-050: kdelibs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-050 (kdelibs).

Libraries for the K Desktop Environment:
KDE Libraries included: kdecore (KDE core library), kdeui (user interface),
kfm (file manager), khtmlw (HTML widget), kio (Input/Output, networking),
kspell (spelling checker), jscript (javascript), kab (addressbook),
kimgio (image manipulation).

Update Information:

A heap overflow flaw was discovered affecting kjs, the
JavaScript interpreter engine used by Konqueror and other
parts of KDE. An attacker could create a malicious web site
containing carefully crafted JavaScript code that would
trigger this flaw and possibly lead to arbitrary code
execution. The Common Vulnerabilities and Exposures project
assigned the name CVE-2006-0019 to this issue.

Users of KDE should upgrade to these updated packages, which
contain a backported patch from the KDE security team
correcting this issue


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs package";
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
if ( rpm_check( reference:"kdelibs-3.5.0-0.4.fc4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kdelibs-", release:"FC4") )
{
 set_kb_item(name:"CVE-2006-0019", value:TRUE);
}
