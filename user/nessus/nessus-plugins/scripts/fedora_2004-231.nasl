#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13750);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Fedora Core 2 2004-231: subversion";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-231 (subversion).

Subversion is a concurrent version control system which enables one
or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes.  Subversion only stores the differences between versions,
instead of every complete file.  Subversion is intended to be a
compelling replacement for CVS.

Update Information:

This update includes the latest release of Subversion, including a
security fix for an issue in the mod_authz_svn Apache authentication
module which could allow a read restriction for a portion of the
repository to be bypassed by a user who has write access to a
different portion of the repository.  This issue does not affect the
svnserve daemon.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-231.shtml
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
if ( rpm_check( reference:"subversion-1.0.6-1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"subversion-devel-1.0.6-1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_dav_svn-1.0.6-1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"subversion-perl-1.0.6-1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"subversion-debuginfo-1.0.6-1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
