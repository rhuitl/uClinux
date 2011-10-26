#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:015
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16243);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1177");
 
 name["english"] = "MDKSA-2005:015: mailman";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:015 (mailman).



Florian Weimer discovered a vulnerability in Mailman, which can be exploited by
malicious people to conduct cross-site scripting attacks.

Input is not properly sanitised by 'scripts/driver' when returning error pages.
This can be exploited to execute arbitrary HTML or script code in a user's
browser session in context of a vulnerable site by tricking a user into
visiting a malicious web site or follow a specially crafted link.
(CVE-2004-1177).



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:015
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
if ( rpm_check( reference:"mailman-2.1.4-2.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.5-7.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mailman-", release:"MDK10.0")
 || rpm_exists(rpm:"mailman-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-1177", value:TRUE);
}
