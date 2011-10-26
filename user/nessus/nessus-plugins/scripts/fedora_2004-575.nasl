#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16052);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1125");
 
 name["english"] = "Fedora Core 3 2004-575: cups";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-575 (cups).

The Common UNIX Printing System provides a portable printing layer for
UNIX operating systems. It has been developed by Easy
Software Products to promote a standard printing solution for all 
UNIX vendors and users.

CUPS provides the System V and Berkeley command-line interfaces.

Update Information:

This package fixes a buffer overflow which may possibly allow attackers
to execute arbitrary code as the 'lp' user. The Common Vulnerabilities
and Exposures projects (cve.mitre.org) has assigned the name CVE-2004-1125 
to this issue.


Solution : http://www.fedoranews.org/blog/index.php?p=227
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cups package";
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
if ( rpm_check( reference:"cups-1.1.22-0.rc1.8.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.22-0.rc1.8.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.22-0.rc1.8.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-debuginfo-1.1.22-0.rc1.8.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"cups-", release:"FC3") )
{
 set_kb_item(name:"CVE-2004-1125", value:TRUE);
}
