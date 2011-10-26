#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:071-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14054);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0015");
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(7912);
 script_cve_id("CVE-2003-0434");
 
 name["english"] = "MDKSA-2003:071-1: xpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:071-1 (xpdf).


Martyn Gilmore discovered flaws in various PDF viewers, including xpdf. An
attacker could place malicious external hyperlinks in a document that, if
followed, could execute arbitary shell commands with the privileges of the
person viewing the PDF document.
Update:
New packages are available as the previous patches that had been applied did not
correct all possible ways of exploiting this issue.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:071-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xpdf package";
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
if ( rpm_check( reference:"xpdf-1.01-4.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpdf-2.01-2.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"xpdf-", release:"MDK9.0")
 || rpm_exists(rpm:"xpdf-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0434", value:TRUE);
}
