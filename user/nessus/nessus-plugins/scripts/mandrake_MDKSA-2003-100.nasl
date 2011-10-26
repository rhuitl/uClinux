#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:100
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14082);
 script_bugtraq_id(8846);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0793", "CVE-2003-0794");
 
 name["english"] = "MDKSA-2003:100: gdm";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:100 (gdm).


Two vulnerabilities were discovered in gdm by Jarno Gassenbauer that would allow
a local attacker to cause gdm to crash or freeze.
The provided packages are patched to fix this problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:100
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gdm package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gdm-2.4.1.6-0.4.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdm-Xnest-2.4.1.6-0.4.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdm-2.4.4.0-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdm-Xnest-2.4.4.0-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gdm-", release:"MDK9.1")
 || rpm_exists(rpm:"gdm-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0793", value:TRUE);
 set_kb_item(name:"CVE-2003-0794", value:TRUE);
}
