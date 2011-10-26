#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13724);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0414", "CVE-2004-0417", "CVE-2004-0418");
 
 name["english"] = "Fedora Core 2 2004-170: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-170 (cvs).

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

While investigating a previously fixed vulnerability, Derek Price
discovered a flaw relating to malformed 'Entry' lines which lead to a
missing NULL terminator. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2004-0414 to this
issue.

Stefan Esser and Sebastian Krahmer conducted an audit of CVS and
fixed a number of issues that may have had security consequences.

Among the issues deemed likely to be exploitable were:

-- a double-free relating to the error_prog_name string
(CVE-2004-0416) -- an argument integer overflow (CVE-2004-0417) --
out-of-bounds writes in serv_notify (CVE-2004-0418).

An attacker who has access to a CVS server may be able to execute
arbitrary code under the UID on which the CVS server is executing.

Users of CVS are advised to upgrade to this updated package, which
updates the cvs package to version 1.11.17, which corrects these
issues.

Red Hat would like to thank Stefan Esser, Sebastian Krahmer, and
Derek Price for auditing, disclosing, and providing patches for these
issues.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-170.shtml
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
if ( rpm_check( reference:"cvs-1.11.17-2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-debuginfo-1.11.17-2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"cvs-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0414", value:TRUE);
 set_kb_item(name:"CVE-2004-0417", value:TRUE);
 set_kb_item(name:"CVE-2004-0418", value:TRUE);
}
