#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:064
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14047);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1155");
 
 name["english"] = "MDKSA-2003:064: kon2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:064 (kon2).


A vulnerability was discovered in kon2, a Kanji emulator for the console. A
buffer overflow in the command line parsing can be exploited, leading to local
users being able to gain root privileges.
These updated packages provide a fix for this vulnerability.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:064
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kon2 package";
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
if ( rpm_check( reference:"kon2-0.3.9b-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kon2-0.3.9b-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kon2-0.3.9b-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kon2-", release:"MDK8.2")
 || rpm_exists(rpm:"kon2-", release:"MDK9.0")
 || rpm_exists(rpm:"kon2-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2002-1155", value:TRUE);
}
