#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:077
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14175);
 script_bugtraq_id(10699);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0645");
 
 name["english"] = "MDKSA-2004:077: wv";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:077 (wv).


iDefense discovered a buffer overflow vulnerability in the wv package which
could allow an attacker to execute arbitrary code with the privileges of the
user running the vulnerable application.
The updated packages are patched to protect against this problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:077
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the wv package";
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
if ( rpm_check( reference:"libwv-1.0_0-1.0.0-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwv-1.0_0-devel-1.0.0-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wv-1.0.0-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwv-1.0_0-1.0.0-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwv-1.0_0-devel-1.0.0-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wv-1.0.0-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"wv-", release:"MDK10.0")
 || rpm_exists(rpm:"wv-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0645", value:TRUE);
}
