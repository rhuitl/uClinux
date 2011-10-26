#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:037
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16461);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0202");
 
 name["english"] = "MDKSA-2005:037: mailman";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:037 (mailman).



A vulnerability was discovered in Mailman, which allows a remote directory
traversal exploit using URLs of the form '.../....///' to access private
Mailman configuration data.

The vulnerability lies in the Mailman/Cgi/private.py file.

Updated packages correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:037
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mailman package";
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
if ( rpm_check( reference:"mailman-2.1.4-2.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.5-7.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mailman-", release:"MDK10.0")
 || rpm_exists(rpm:"mailman-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0202", value:TRUE);
}
