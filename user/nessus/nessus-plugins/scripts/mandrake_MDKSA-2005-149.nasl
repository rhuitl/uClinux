#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:149
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19905);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2672");
 
 name["english"] = "MDKSA-2005:149: lm_sensors";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:149 (lm_sensors).



Javier Fernandez-Sanguino Pena discovered that the pwmconfig script in the
lm_sensors package created temporary files in an insecure manner. This could
allow a symlink attack to create or overwrite arbitrary files with full root
privileges because pwmconfig is typically executed by root.

The updated packages have been patched to correct this problem by using mktemp
to create the temporary files.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:149
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lm_sensors package";
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
if ( rpm_check( reference:"liblm_sensors3-2.8.4-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"liblm_sensors3-devel-2.8.4-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"liblm_sensors3-static-devel-2.8.4-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lm_sensors-2.8.4-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"liblm_sensors3-2.8.7-7.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"liblm_sensors3-devel-2.8.7-7.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"liblm_sensors3-static-devel-2.8.7-7.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lm_sensors-2.8.7-7.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"liblm_sensors3-2.9.0-4.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"liblm_sensors3-devel-2.9.0-4.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"liblm_sensors3-static-devel-2.9.0-4.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lm_sensors-2.9.0-4.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"lm_sensors-", release:"MDK10.0")
 || rpm_exists(rpm:"lm_sensors-", release:"MDK10.1")
 || rpm_exists(rpm:"lm_sensors-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2672", value:TRUE);
}
