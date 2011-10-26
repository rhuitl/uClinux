#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14808);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0749");
 
 name["english"] = "Fedora Core 2 2004-318: subversion";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-318 (subversion).

Subversion is a concurrent version control system which enables one
or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes.  Subversion only stores the differences between versions,
instead of every complete file.  Subversion is intended to be a
compelling replacement for CVS.

Update Information:

This update includes the latest stable release of Subversion, including
a security fix for information disclosure bugs in handling of metadata
(such as log messages) in repositories using mod_authz_svn for
path-based access-control (CVE-2004-0749).



Solution : http://www.fedoranews.org/updates/FEDORA-2004-318.shtml
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
if ( rpm_check( reference:"subversion-1.0.8-1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"subversion-devel-1.0.8-1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_dav_svn-1.0.8-1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"subversion-perl-1.0.8-1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"subversion-debuginfo-1.0.8-1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"subversion-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0749", value:TRUE);
}
