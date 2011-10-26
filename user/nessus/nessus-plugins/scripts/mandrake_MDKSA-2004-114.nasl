#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:114
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15549);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0888");
 
 name["english"] = "MDKSA-2004:114: gpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:114 (gpdf).


Chris Evans discovered numerous vulnerabilities in the xpdf package, which also
effect software using embedded xpdf code, such as gpdf:
Multiple integer overflow issues affecting xpdf-2.0 and xpdf-3.0. Also programs
like gpdf which have embedded versions of xpdf. These can result in writing an
arbitrary byte to an attacker controlled location which probably could lead to
arbitrary code execution.
The updated packages are patched to protect against these vulnerabilities.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:114
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gpdf package";
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
if ( rpm_check( reference:"gpdf-0.112-2.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gpdf-", release:"MDK10.0") )
{
 set_kb_item(name:"CVE-2004-0888", value:TRUE);
}
