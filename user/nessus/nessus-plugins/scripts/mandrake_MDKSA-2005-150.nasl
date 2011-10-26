#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:150
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19906);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2547");
 
 name["english"] = "MDKSA-2005:150: bluez-utils";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:150 (bluez-utils).



A vulnerability in bluez-utils was discovered by Henryk Plotz. Due to missing
input sanitizing, it was possible for an attacker to execute arbitrary commands
supplied as a device name from the remote bluetooth device.

The updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:150
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the bluez-utils package";
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
if ( rpm_check( reference:"bluez-utils-2.4-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bluez-utils-2.10-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bluez-utils-cups-2.10-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bluez-utils-2.14-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bluez-utils-cups-2.14-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"bluez-utils-", release:"MDK10.0")
 || rpm_exists(rpm:"bluez-utils-", release:"MDK10.1")
 || rpm_exists(rpm:"bluez-utils-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2547", value:TRUE);
}
