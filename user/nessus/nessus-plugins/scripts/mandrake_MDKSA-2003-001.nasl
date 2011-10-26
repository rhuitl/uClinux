#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:001
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13986);
 script_bugtraq_id(6433, 6434, 6435, 6436, 6437, 6438, 6439, 6440, 6475);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2002-1366", "CVE-2002-1367", "CVE-2002-1368", "CVE-2002-1369", "CVE-2002-1371", "CVE-2002-1372", "CVE-2002-1383", "CVE-2002-1384");
 
 name["english"] = "MDKSA-2003:001: cups";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:001 (cups).


iDefense reported several security problems in CUPS that can lead to local and
remote root compromise. An integer overflow in the HTTP interface can be used to
gain remote access with CUPS privilege. A local file race condition can be used
to gain root privilege, although the previous bug must be exploited first. An
attacker can remotely add printers to the vulnerable system. A remote DoS can be
accomplished due to negative length in the memcpy() call. An integer overflow in
image handling code can be used to gain higher privilege. An attacker can gain
local root privilege due to a buffer overflow of the 'options' buffer. A design
problem can be exploited to gain local root access, however this needs an added
printer (which can also be done, as per a previously noted bug). Wrong handling
of zero-width images can be abused to gain higher privilege. Finally, a file
descriptor leak and DoS due to missing checks of return values of file/socket
operations.
MandrakeSoft recommends all users upgrade these CUPS packages immediately.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:001
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
if ( rpm_check( reference:"cups-1.1.18-1.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.18-1.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.18-1.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"printer-testpages-1.1.18-1.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.18-1.4mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.1.18-1.4mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.18-1.4mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups1-1.1.18-1.4mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups1-devel-1.1.18-1.4mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"printer-testpages-1.1.18-1.4mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.18-1.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.1.18-1.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.18-1.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups1-1.1.18-1.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups1-devel-1.1.18-1.4mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.18-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.1.18-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.18-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups1-1.1.18-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups1-devel-1.1.18-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.18-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.1.18-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.18-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups1-1.1.18-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups1-devel-1.1.18-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cups-", release:"MDK7.2")
 || rpm_exists(rpm:"cups-", release:"MDK8.0")
 || rpm_exists(rpm:"cups-", release:"MDK8.1")
 || rpm_exists(rpm:"cups-", release:"MDK8.2")
 || rpm_exists(rpm:"cups-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1366", value:TRUE);
 set_kb_item(name:"CVE-2002-1367", value:TRUE);
 set_kb_item(name:"CVE-2002-1368", value:TRUE);
 set_kb_item(name:"CVE-2002-1369", value:TRUE);
 set_kb_item(name:"CVE-2002-1371", value:TRUE);
 set_kb_item(name:"CVE-2002-1372", value:TRUE);
 set_kb_item(name:"CVE-2002-1383", value:TRUE);
 set_kb_item(name:"CVE-2002-1384", value:TRUE);
}
