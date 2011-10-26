#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:048
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17277);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0490");
 
 name["english"] = "MDKSA-2005:048: curl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:048 (curl).



'infamous41md' discovered a buffer overflow vulnerability in libcurl's NTLM
authorization base64 decoding. This could allow a remote attacker using a
prepared remote server to execute arbitrary code as the user running curl.

The updated packages are patched to deal with these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:048
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the curl package";
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
if ( rpm_check( reference:"curl-7.11.0-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcurl2-7.11.0-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcurl2-devel-7.11.0-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"curl-7.12.1-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcurl3-7.12.1-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcurl3-devel-7.12.1-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"curl-", release:"MDK10.0")
 || rpm_exists(rpm:"curl-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0490", value:TRUE);
}
