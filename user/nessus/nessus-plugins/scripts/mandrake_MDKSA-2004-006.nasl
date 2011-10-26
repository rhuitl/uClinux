#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:006-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14106);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2004-0006", "CVE-2004-0007", "CVE-2004-0008");
 
 name["english"] = "MDKSA-2004:006-1: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:006-1 (gaim).


A number of vulnerabilities were discovered in the gaim instant messenger
program by Steffan Esser, versions 0.75 and earlier. Thanks to Jacques A.
Vidrine for providing initial patches.
Multiple buffer overflows exist in gaim 0.75 and earlier: When parsing cookies
in a Yahoo web connection; YMSG protocol overflows parsing the Yahoo login
webpage; a YMSG packet overflow; flaws in the URL parser; and flaws in the HTTP
Proxy connect (CAN-2004-006).
A buffer overflow in gaim 0.74 and earlier in the Extract Info Field Function
used for MSN and YMSG protocol handlers (CAN-2004-007).
An integer overflow in gaim 0.74 and earlier, when allocating memory for a
directIM packet results in a heap overflow (CVE-2004-0008).
Update:
The patch used to correct the problem was slightly malformed and could cause an
infinite loop and crash with the Yahoo protocol. The new packages have a
corrected patch that resolves the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:006-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gaim package";
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
if ( rpm_check( reference:"gaim-0.75-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-encrypt-0.75-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-0.75-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-devel-0.75-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-0.75-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-encrypt-0.75-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-festival-0.75-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-perl-0.75-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-0.75-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-devel-0.75-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gaim-", release:"MDK9.1")
 || rpm_exists(rpm:"gaim-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0006", value:TRUE);
 set_kb_item(name:"CVE-2004-0007", value:TRUE);
 set_kb_item(name:"CVE-2004-0008", value:TRUE);
}
