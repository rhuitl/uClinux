#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14765);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0786");
 
 name["english"] = "Fedora Core 2 2004-308: apr-util";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-308 (apr-util).

The mission of the Apache Portable Runtime (APR) is to provide a
free library of C data structures and routines.  This library
contains additional utility interfaces for APR; including support
for XML, LDAP, database interfaces, URI parsing and more.

Update Information:

Testing using the Codenomicon HTTP Test Tool performed by the Apache
Software Foundation security group and Red Hat uncovered an input
validation issue in the IPv6 URI parsing routines in the apr-util
library.  If a remote attacker sent a request including a carefully
crafted URI, an httpd child process could be made to crash.  The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0786 to this issue.

This update includes a backported fix for this issue.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-308.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the apr-util package";
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
if ( rpm_check( reference:"apr-util-0.9.4-14.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apr-util-devel-0.9.4-14.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apr-util-debuginfo-0.9.4-14.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"apr-util-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0786", value:TRUE);
}
