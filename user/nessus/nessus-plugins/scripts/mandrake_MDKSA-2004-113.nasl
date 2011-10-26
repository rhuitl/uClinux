#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:113
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15548);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0888", "CVE-2004-0889");
 
 name["english"] = "MDKSA-2004:113: xpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:113 (xpdf).


Chris Evans discovered numerous vulnerabilities in the xpdf package:
Multiple integer overflow issues affecting xpdf-2.0 and xpdf-3.0. Also programs
like cups which have embedded versions of xpdf. These can result in writing an
arbitrary byte to an attacker controlled location which probably could lead to
arbitrary code execution. (CVE-2004-0888)
Multiple integer overflow issues affecting xpdf-3.0 only. These can result in
DoS or possibly arbitrary code execution. (CVE-2004-0889)
Chris also discovered issues with infinite loop logic error affecting xpdf-3.0
only.
The updated packages are patched to deal with these issues.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:113
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
if ( rpm_check( reference:"xpdf-3.00-5.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"xpdf-", release:"MDK10.0") )
{
 set_kb_item(name:"CVE-2004-0888", value:TRUE);
 set_kb_item(name:"CVE-2004-0889", value:TRUE);
}
