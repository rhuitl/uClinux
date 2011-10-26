#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:064
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17670);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0664");
 
 name["english"] = "MDKSA-2005:064: libexif";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:064 (libexif).



A buffer overflow was discovered in the way libexif parses EXIF tags. An
attacker could exploit this by creating a special EXIF image file which could
cause image viewers linked against libexif to crash.

The updated packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:064
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libexif package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"libexif9-0.5.12-3.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libexif9-devel-0.5.12-3.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libexif9-0.5.12-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libexif9-devel-0.5.12-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libexif-", release:"MDK10.0")
 || rpm_exists(rpm:"libexif-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0664", value:TRUE);
}
