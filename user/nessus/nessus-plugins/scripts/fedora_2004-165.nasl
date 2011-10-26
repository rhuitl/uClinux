#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13719);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0413");
 
 name["english"] = "Fedora Core 1 2004-165: subversion";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-165 (subversion).

Subversion is a concurrent version control system which enables one
or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes.  Subversion only stores the differences between versions,
instead of every complete file.  Subversion is intended to be a
compelling replacement for CVS.

Update Information:

A heap overflow vulnerability was discovered in the svn:// protocol
handling library, libsvn_ra_svn.  If using the svnserve daemon,
an unauthenticated client may be able execute arbitrary code as
the user the daemon runs as.  The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2004-0413.
                                                                                               
This issue does not affect the mod_dav_svn module.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-165.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the subversion package";
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
if ( rpm_check( reference:"subversion-0.32.1-5", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"subversion-devel-0.32.1-5", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_dav_svn-0.32.1-5", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"subversion-debuginfo-0.32.1-5", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"subversion-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0413", value:TRUE);
}
