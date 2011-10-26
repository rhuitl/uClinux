#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19654);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0753");
 
 name["english"] = "Fedora Core 3 2005-330: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-330 (cvs).

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

* Mon Apr 18 2005 Martin Stransky <stransky redhat com> 1.11.17-6.FC3
- add security fix CVE-2005-0753 (Derek Price)


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cvs package";
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
if ( rpm_check( reference:"cvs-1.11.17-6.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-debuginfo-1.11.17-6.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"cvs-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0753", value:TRUE);
}
