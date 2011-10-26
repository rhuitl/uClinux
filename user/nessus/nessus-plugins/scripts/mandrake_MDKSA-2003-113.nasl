#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:113
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14095);
 script_bugtraq_id(9117);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0972");
 
 name["english"] = "MDKSA-2003:113: screen";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:113 (screen).


A vulnerability was discovered and fixed in screen by Timo Sirainen who found an
exploitable buffer overflow that allowed privilege escalation. This
vulnerability also has the potential to allow attackers to gain control of
another user's screen session. The ability to exploit is not trivial and
requires approximately 2GB of data to be transferred in order to do so.
Updated packages are available that fix the vulnerability.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:113
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the screen package";
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
if ( rpm_check( reference:"screen-3.9.11-4.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"screen-3.9.13-2.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"screen-3.9.15-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"screen-", release:"MDK9.0")
 || rpm_exists(rpm:"screen-", release:"MDK9.1")
 || rpm_exists(rpm:"screen-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0972", value:TRUE);
}
