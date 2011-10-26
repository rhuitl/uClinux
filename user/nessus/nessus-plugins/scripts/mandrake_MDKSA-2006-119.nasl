#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:119
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22019);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2194");
 
 name["english"] = "MDKSA-2006:119: ppp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:119 (ppp).



Marcus Meissner discovered that pppd's winbind plugin did not check for

the result of the setuid() call which could allow an attacker to

exploit this on systems with certain PAM limits enabled to execute the

NTLM authentication helper as root. This could possibly lead to

privilege escalation dependant upon the local winbind configuration.



Updated packages have been patched ot correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:119
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ppp package";
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
if ( rpm_check( reference:"ppp-2.4.3-9.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ppp-devel-2.4.3-9.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ppp-dhcp-2.4.3-9.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ppp-pppoatm-2.4.3-9.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ppp-pppoe-2.4.3-9.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ppp-prompt-2.4.3-9.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ppp-radius-2.4.3-9.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ppp-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-2194", value:TRUE);
}
