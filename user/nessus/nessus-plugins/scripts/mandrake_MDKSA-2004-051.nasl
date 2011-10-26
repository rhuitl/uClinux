#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:051
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14150);
 script_bugtraq_id(10412);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0412");
 
 name["english"] = "MDKSA-2004:051: mailman";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:051 (mailman).


Mailman versions >= 2.1 have an issue where 3rd parties can retrieve member
passwords from the server. The updated packages have a patch backported from
2.1.5 to correct the issue.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:051
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mailman package";
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
if ( rpm_check( reference:"mailman-2.1.4-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.2-9.4.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mailman-", release:"MDK10.0")
 || rpm_exists(rpm:"mailman-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0412", value:TRUE);
}
