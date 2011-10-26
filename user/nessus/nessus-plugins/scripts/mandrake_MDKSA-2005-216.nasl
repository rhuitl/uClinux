#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:216
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20448);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3531");
 
 name["english"] = "MDKSA-2005:216: fuse";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:216 (fuse).



Thomas Beige found that fusermount failed to securely handle special characters
specified in mount points, which could allow a local attacker to corrupt the
contents of /etc/mtab by mounting over a maliciously-named directory using
fusermount. This could potentially allow the attacker to set unauthorized mount
options. This is only possible when fusermount is installed setuid root, which
is the case in Mandriva Linux. The updated packages have been patched to
address these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:216
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the fuse package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"dkms-fuse-2.3.0-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fuse-2.3.0-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libfuse2-2.3.0-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libfuse2-devel-2.3.0-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libfuse2-static-devel-2.3.0-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"fuse-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3531", value:TRUE);
}
