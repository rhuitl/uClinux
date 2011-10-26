#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:060
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21149);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1354");
 
 name["english"] = "MDKSA-2006:060: freeradius";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:060 (freeradius).



An unspecified vulnerability in FreeRADIUS 1.0.0 up to 1.1.0 allows remote
attackers to bypass authentication or cause a denial of service (server crash)
via 'Insufficient input validation' in the EAP-MSCHAPv2 state machine module.
Updated packages have been patched to correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:060
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the freeradius package";
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
if ( rpm_check( reference:"freeradius-1.0.4-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libfreeradius1-1.0.4-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libfreeradius1-devel-1.0.4-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libfreeradius1-krb5-1.0.4-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libfreeradius1-ldap-1.0.4-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libfreeradius1-mysql-1.0.4-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libfreeradius1-postgresql-1.0.4-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libfreeradius1-unixODBC-1.0.4-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"freeradius-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-1354", value:TRUE);
}
