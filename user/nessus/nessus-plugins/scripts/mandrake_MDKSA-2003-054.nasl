#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:054
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14038);
 script_bugtraq_id(7066);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0124");
 
 name["english"] = "MDKSA-2003:054: man";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:054 (man).


A difficult to exploit vulnerability was discovered in versions of man prior to
1.5l. A bug exists in man that could cause a program named 'unsafe' to be
executed due to a malformed man file. In order to exploit this bug, a local
attacker would have to be able to get another user to read the malformed man
file, and the attacker would also have to create a file called 'unsafe' that
would be located somewhere in the victim's path.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:054
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the man package";
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
if ( rpm_check( reference:"man-1.5j-4.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"man-1.5k-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"man-1.5k-8.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"man-", release:"MDK8.2")
 || rpm_exists(rpm:"man-", release:"MDK9.0")
 || rpm_exists(rpm:"man-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0124", value:TRUE);
}
