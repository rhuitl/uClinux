#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19435);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2097");
 
 name["english"] = "Fedora Core 3 2005-730: xpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-730 (xpdf).

Xpdf is an X Window System based viewer for Portable Document Format
(PDF) files. Xpdf is a small and efficient program which uses
standard X fonts.

Update Information:

A flaw was discovered in Xpdf in that an attacker could
construct a carefully crafted PDF file that would cause Xpdf
to consume all available disk space in /tmp when opened. The
Common Vulnerabilities and Exposures project assigned the name
CVE-2005-2097 to this issue.

Users of xpdf should upgrade to this updated package, which
contains a backported patch to resolve this issue.


Solution : http://www.fedoranews.org/blog/index.php?p=838
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xpdf package";
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
if ( rpm_check( reference:"xpdf-3.00-10.6.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-debuginfo-3.00-10.6.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"xpdf-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2097", value:TRUE);
}
