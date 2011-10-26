#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:182
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20042);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-3185");
 
 name["english"] = "MDKSA-2005:182: curl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:182 (curl).



A vulnerability in libcurl's NTLM function can overflow a stack-based buffer if
given too long a user name or domain name in NTLM authentication is enabled and
either a) pass a user and domain name to libcurl that together are longer than
192 bytes or b) allow (lib)curl to follow HTTP redirects and the new URL
contains a URL with a user and domain name that together are longer than 192
bytes.

The updated packages have been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:182
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
if ( rpm_check( reference:"curl-7.12.1-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcurl3-7.12.1-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcurl3-devel-7.12.1-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"curl-7.13.1-2.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcurl3-7.13.1-2.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcurl3-devel-7.13.1-2.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"curl-7.14.0-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcurl3-7.14.0-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcurl3-devel-7.14.0-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"curl-", release:"MDK10.1")
 || rpm_exists(rpm:"curl-", release:"MDK10.2")
 || rpm_exists(rpm:"curl-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3185", value:TRUE);
}
