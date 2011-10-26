#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:020
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20809);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3732");
 
 name["english"] = "MDKSA-2006:020: ipsec-tools";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:020 (ipsec-tools).



The Internet Key Exchange version 1 (IKEv1) implementation (isakmp_agg.c) in
ipsec-tools racoon before 0.6.3, when running in aggressive mode, allows remote
attackers to cause a denial of service (null dereference and crash) via crafted
IKE packets, as demonstrated by the PROTOS ISAKMP Test Suite for IKEv1. The
updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:020
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ipsec-tools package";
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
if ( rpm_check( reference:"ipsec-tools-0.2.5-2.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libipsec-tools0-0.2.5-2.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ipsec-tools-0.5-4.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libipsec0-0.5-4.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libipsec0-devel-0.5-4.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ipsec-tools-0.5.2-5.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libipsec0-0.5.2-5.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libipsec0-devel-0.5.2-5.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ipsec-tools-", release:"MDK10.1")
 || rpm_exists(rpm:"ipsec-tools-", release:"MDK10.2")
 || rpm_exists(rpm:"ipsec-tools-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3732", value:TRUE);
}
