#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:014
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14114);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0104", "CVE-2004-0105");
 
 name["english"] = "MDKSA-2004:014: metamail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:014 (metamail).


Two format string and two buffer overflow vulnerabilities were discovered in
metamail by Ulf Harnhammar. The updated packages are patched to fix these holes.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:014
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the metamail package";
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
if ( rpm_check( reference:"metamail-2.7-9.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"metamail-2.7-9.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"metamail-2.7-9.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"metamail-", release:"MDK9.0")
 || rpm_exists(rpm:"metamail-", release:"MDK9.1")
 || rpm_exists(rpm:"metamail-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0104", value:TRUE);
 set_kb_item(name:"CVE-2004-0105", value:TRUE);
}
