#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:222
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20453);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3573", "CVE-2005-4153");
 
 name["english"] = "MDKSA-2005:222: mailman";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:222 (mailman).



Scrubber.py in Mailman 2.1.4 - 2.1.6 does not properly handle UTF8 character
encodings in filenames of e-mail attachments, which allows remote attackers to
cause a denial of service. (CVE-2005-3573) In addition, these versions of
mailman have an issue where the server will fail with an Overflow on bad date
data in a processed message. The version of mailman in Corporate Server 2.1
does not contain the above vulnerable code. Updated packages are patched to
correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:222
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mailman package";
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
if ( rpm_check( reference:"mailman-2.1.5-7.5.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.5-15.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.6-6.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mailman-", release:"MDK10.1")
 || rpm_exists(rpm:"mailman-", release:"MDK10.2")
 || rpm_exists(rpm:"mailman-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3573", value:TRUE);
 set_kb_item(name:"CVE-2005-4153", value:TRUE);
}
