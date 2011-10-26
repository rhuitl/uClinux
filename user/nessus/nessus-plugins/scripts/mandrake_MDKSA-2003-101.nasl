#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:101
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14083);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0792");
 
 name["english"] = "MDKSA-2003:101: fetchmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:101 (fetchmail).


A bug was discovered in fetchmail 6.2.4 where a specially crafted email message
can cause fetchmail to crash.
Thanks to Nalin Dahyabhai of Red Hat for providing the patch to fix the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:101
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the fetchmail package";
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
if ( rpm_check( reference:"fetchmail-6.2.4-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.2.4-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.2.4-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"fetchmail-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0792", value:TRUE);
}
