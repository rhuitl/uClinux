#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:115
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21777);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-3242");
 
 name["english"] = "MDKSA-2006:115: mutt";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:115 (mutt).



A stack-based buffer overflow in the browse_get_namespace function in

imap/browse.c of Mutt allows remote attackers to cause a denial of service

(crash) or execute arbitrary code via long namespaces received from the

IMAP server.



Updated packages have been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:115
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mutt package";
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
if ( rpm_check( reference:"mutt-1.5.6i-5.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mutt-utf8-1.5.6i-5.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mutt-1.5.9i-9.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mutt-utf8-1.5.9i-9.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mutt-", release:"MDK10.2")
 || rpm_exists(rpm:"mutt-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-3242", value:TRUE);
}
