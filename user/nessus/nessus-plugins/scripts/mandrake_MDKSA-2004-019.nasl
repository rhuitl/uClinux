#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:019
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14119);
 script_bugtraq_id(9836);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0150");
 
 name["english"] = "MDKSA-2004:019: python";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:019 (python).


A buffer overflow in python 2.2's getaddrinfo() function was discovered by
Sebastian Schmidt. If python 2.2 is built without IPv6 support, an attacker
could configure their name server to let a hostname resolve to a special IPv6
address, which could contain a memory address where shellcode is placed. This
problem does not affect python versions prior to 2.2 or versions 2.2.2+, and it
also doesn't exist if IPv6 support is enabled.
The updated packages have been patched to correct the problem. Thanks to
Sebastian for both the discovery and patch.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:019
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the python package";
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
if ( rpm_check( reference:"libpython2.2-2.2.1-14.4.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpython2.2-devel-2.2.1-14.4.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-2.2.1-14.4.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-base-2.2.1-14.4.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-docs-2.2.1-14.4.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tkinter-2.2.1-14.4.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"python-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2004-0150", value:TRUE);
}
