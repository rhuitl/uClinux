#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16357);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0888");
 
 name["english"] = "Fedora Core 2 2005-135: xpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-135 (xpdf).

Xpdf is an X Window System based viewer for Portable Document Format
(PDF) files. Xpdf is a small and efficient program which uses
standard X fonts.


* Wed Feb 09 2005 Than Ngo
1:3.00-3.8

- More fixing of CVE-2004-0888 patch (bug #135393, #147524)



Solution : http://www.fedoranews.org/blog/index.php?p=381
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
if ( rpm_check( reference:"xpdf-3.00-3.8", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-debuginfo-3.00-3.8", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"xpdf-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0888", value:TRUE);
}
