#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:010
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16219);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0020");
 
 name["english"] = "MDKSA-2005:010: playmidi";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:010 (playmidi).



Erik Sjolund discovered a buffer overflow in playmidi that could be exploited
by a local attacker if installed setuid root. Note that by default
Mandrakelinux does not ship playmidi installed setuid root.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:010
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the playmidi package";
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
if ( rpm_check( reference:"playmidi-2.5-3.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"playmidi-X11-2.5-3.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"playmidi-2.5-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"playmidi-X11-2.5-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"playmidi-", release:"MDK10.0")
 || rpm_exists(rpm:"playmidi-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0020", value:TRUE);
}
