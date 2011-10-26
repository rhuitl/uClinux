#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:041
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20940);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0670");
 
 name["english"] = "MDKSA-2006:041: bluez-hcidump";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:041 (bluez-hcidump).



Buffer overflow in l2cap.c in hcidump allows remote attackers to cause a denial
of service (crash) through a wireless Bluetooth connection via a malformed
Logical Link Control and Adaptation Protocol (L2CAP) packet. The updated
packages have been patched to correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:041
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the bluez-hcidump package";
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
if ( rpm_check( reference:"bluez-hcidump-1.16-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bluez-hcidump-1.24-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"bluez-hcidump-", release:"MDK10.2")
 || rpm_exists(rpm:"bluez-hcidump-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-0670", value:TRUE);
}
