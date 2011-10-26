#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:055
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13957);
 script_bugtraq_id(3357);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2001-1034");
 
 name["english"] = "MDKSA-2002:055: hylafax";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:055 (hylafax).


Numerous vulnerabilities in the HylaFAX product exist in versions prior to
4.1.3. It does not check the TSI string which is received from remote FAX
systems before using it in logging and other places. A remote sender using a
specially formatted TSI string can cause the faxgetty program to segfault,
resulting in a denial of service. Format string vulnerabilities were also
discovered by Christer Oberg, which exist in a number of utilities bundled with
HylaFax, such as faxrm, faxalter, faxstat, sendfax, sendpage, and faxwatch. If
any of these tools are setuid, they could be used to elevate system privileges.
Mandrake Linux does not, by default, install these tools setuid. Finally, Lee
Howard discovered that faxgetty would segfault due to a buffer overflow after
receiving a very large line of image data. This vulnerability could conceivably
be used to execute arbitrary commands on the system as root, and could also be
exploited more easily as a denial of sevice.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:055
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the hylafax package";
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
if ( rpm_check( reference:"hylafax-4.1-0.11mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.1-0.11mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.1-0.11mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.1-0.11mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.1-0.11mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.1-0.11mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.1.3-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.1.3-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.1.3-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.1.1-4.1.3-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.1.1-devel-4.1.3-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.1.3-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.1.3-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.1.3-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.1.1-4.1.3-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.1.1-devel-4.1.3-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.1.3-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.1.3-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.1.3-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.1.1-4.1.3-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.1.1-devel-4.1.3-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"hylafax-", release:"MDK7.1")
 || rpm_exists(rpm:"hylafax-", release:"MDK7.2")
 || rpm_exists(rpm:"hylafax-", release:"MDK8.0")
 || rpm_exists(rpm:"hylafax-", release:"MDK8.1")
 || rpm_exists(rpm:"hylafax-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2001-1034", value:TRUE);
}
