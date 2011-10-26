#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13691);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0180");
 
 name["english"] = "Fedora Core 1 2004-110: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-110 (cvs).

CVS (Concurrent Version System) is a version control system that can
record the history of your files (usually, but not always, source
code). CVS only stores the differences between versions, instead of
every version of every file you have ever created. CVS also keeps a log
of who, when, and why changes occurred.

CVS is very helpful for managing releases and controlling the
concurrent editing of source files among multiple authors. Instead of
providing version control for a collection of files in a single
directory, CVS provides version control for a hierarchical collection
of directories consisting of revision controlled files. These
directories and files can then be combined together to form a software
release.

Update Information:

The client for CVS before 1.11.15 allows a remote malicious CVS server
to create arbitrary files using certain RCS diff files that use
absolute pathnames during checkouts or updates.

Updated packages were made available in April 2004 however the original
update notification email did not make it to fedora-announce-list at
that time.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-110.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cvs package";
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
if ( rpm_check( reference:"cvs-1.11.15-1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-debuginfo-1.11.15-1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"cvs-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0180", value:TRUE);
}
