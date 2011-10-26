#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:104
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14086);
 script_bugtraq_id(7637);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0788");
 
 name["english"] = "MDKSA-2003:104: cups";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:104 (cups).


A bug in versions of CUPS prior to 1.1.19 was reported by Paul Mitcheson in the
Internet Printing Protocol (IPP) implementation would result in CUPS going into
a busy loop, which could result in a Denial of Service (DoS) condition. To be
able to exploit this problem, an attacker would need to be able to make a TCP
connection to the IPP port (port 631 by default).
The provided packages have been patched to correct this problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:104
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cups package";
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
if ( rpm_check( reference:"cups-1.1.18-2.2.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.1.18-2.2.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.18-2.2.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups1-1.1.18-2.2.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups1-devel-1.1.18-2.2.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cups-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0788", value:TRUE);
}
