#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16050);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1125");
 
 name["english"] = "Fedora Core 2 2004-572: xpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-572 (xpdf).

Xpdf is an X Window System based viewer for Portable Document Format
(PDF) files. Xpdf is a small and efficient program which uses
standard X fonts.

Update Information:

This package fixes a buffer overflow which allows attackers to cause
the
xpdf application to crash, and possibly to execute arbitrary code. The
Common Vulnerabilities and Exposures projects (cve.mitre.org) has
assigned
the name CVE-2004-1125 to this issue.



Solution : http://www.fedoranews.org/blog/index.php?p=228
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xpdf package";
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
if ( rpm_check( reference:"xpdf-3.00-3.6", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-debuginfo-3.00-3.6", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"xpdf-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-1125", value:TRUE);
}
