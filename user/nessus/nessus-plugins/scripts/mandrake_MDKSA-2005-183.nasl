#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:183
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20430);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3185");
 
 name["english"] = "MDKSA-2005:183: wget";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:183 (wget).



A vulnerability in libcurl's NTLM function can overflow a stack-based buffer if
given too long a user name or domain name in NTLM authentication is enabled and
either a) pass a user and domain name to libcurl that together are longer than
192 bytes or b) allow (lib)curl to follow HTTP redirects and the new URL
contains a URL with a user and domain name that together are longer than 192
bytes.

Wget, as of version 1.10, uses the NTLM code from libcurl and is also
vulnerable to this issue.

The updated packages have been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:183
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the wget package";
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
if ( rpm_check( reference:"wget-1.10-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"wget-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3185", value:TRUE);
}
