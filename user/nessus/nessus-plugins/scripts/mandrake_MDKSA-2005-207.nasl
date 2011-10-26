#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:207
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20441);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2974", "CVE-2005-3350");
 
 name["english"] = "MDKSA-2005:207: libungif";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:207 (libungif).



Several bugs have been discovered in the way libungif decodes GIF images. These
allow an attacker to create a carefully crafted GIF image file in such a way
that it could cause applications linked with libungif to crash or execute
arbitrary code when the file is opened by the user. The updated packages have
been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:207
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libungif package";
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
if ( rpm_check( reference:"libungif4-4.1.2-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif4-devel-4.1.2-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif4-static-devel-4.1.2-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif-progs-4.1.2-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif4-4.1.3-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif4-devel-4.1.3-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif4-static-devel-4.1.3-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif-progs-4.1.3-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif4-4.1.3-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif4-devel-4.1.3-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif4-static-devel-4.1.3-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif-progs-4.1.3-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libungif-", release:"MDK10.1")
 || rpm_exists(rpm:"libungif-", release:"MDK10.2")
 || rpm_exists(rpm:"libungif-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-2974", value:TRUE);
 set_kb_item(name:"CVE-2005-3350", value:TRUE);
}
