#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:062
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14045);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0195");
 
 name["english"] = "MDKSA-2003:062: cups";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:062 (cups).


A Denial of Service (DoS) vulnerability was discovered in the CUPS printing
system by Phil D'Amore of Red Hat. The IPP (Internet Printing Protocol) that
CUPS uses is single-threaded and can only service one request at a time. A
malicious user could create a partial request that does not time out and cause a
Denial of Service condition where CUPS will not respond to other printing
requests. This can only be done if the malicious user can create a TCP
connection to the IPP port (631 by default).
This vulnerability has been fixed upstream in CUPS 1.1.19 and packages of
previous versions have been fixed to correct the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:062
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
if ( rpm_check( reference:"cups-1.1.18-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.1.18-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.18-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups1-1.1.18-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups1-devel-1.1.18-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.18-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.1.18-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.18-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups1-1.1.18-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups1-devel-1.1.18-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.19-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.1.19-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.19-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups1-1.1.19-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups1-devel-1.1.19-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cups-", release:"MDK8.2")
 || rpm_exists(rpm:"cups-", release:"MDK9.0")
 || rpm_exists(rpm:"cups-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0195", value:TRUE);
}
