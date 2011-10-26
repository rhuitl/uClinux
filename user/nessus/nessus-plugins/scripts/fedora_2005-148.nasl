#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17137);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0011");
 
 name["english"] = "Fedora Core 3 2005-148: kdeedu";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-148 (kdeedu).

Educational/Edutainment applications for KDE


* Tue Feb 8 2005 Than Ngo
3.3.1-2.3

- More fixing of CVE-2005-0011 patch

* Tue Feb 1 2005 Than Ngo
3.3.1-2.2

- Apply patch to fix buffer overflow in fliccd, CVE-2005-0011
(#146290)
- replace kgeo (#142367)



Solution : http://www.fedoranews.org/blog/index.php?p=403
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdeedu package";
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
if ( rpm_check( reference:"kdeedu-3.3.1-2.3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdeedu-devel-3.3.1-2.3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdeedu-debuginfo-3.3.1-2.3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kdeedu-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0011", value:TRUE);
}
