#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:038-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13943);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0010");
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2002-0400", "CVE-2002-0651");
 
 name["english"] = "MDKSA-2002:038-1: bind";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:038-1 (bind).


A vulnerability was discovered in the BIND9 DNS server in versions prior to
9.2.1. An error condition will trigger the shutdown of the server when the
rdataset parameter to the dns_message_findtype() function in message.c is not
NULL as expected. This condition causes the server to assert an error message
and shutdown the BIND server. The error condition can be remotely exploited by a
special DNS packet. This can only be used to create a Denial of Service on the
server; the error condition is correctly detected, so it will not allow an
attacker to execute arbitrary code on the server.
Update:
Sascha Kettler noticed that the version of BIND9 supplied originally was in fact
9.2.1RC1 and mis-labelled as 9.2.1. The packages provided in this update are
BIND 9.2.1 final. Likewise, the buffer overflow in the DNS resolver libraries,
as noted in MDKSA-2002:043, has also been fixed. Thanks to Bernhard
Rosenkraenzer at Red Hat for backporting the patches from 8.3.3 to 9.2.1.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:038-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the bind package";
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
if ( rpm_check( reference:"bind-9.2.1-2.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind-devel-9.2.1-2.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind-utils-9.2.1-2.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"caching-nameserver-8.1-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind-9.2.1-2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind-devel-9.2.1-2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind-utils-9.2.1-2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"caching-nameserver-8.1-3.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind-9.2.1-2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind-devel-9.2.1-2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind-utils-9.2.1-2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"caching-nameserver-8.1-3.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"bind-", release:"MDK8.0")
 || rpm_exists(rpm:"bind-", release:"MDK8.1")
 || rpm_exists(rpm:"bind-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-0400", value:TRUE);
 set_kb_item(name:"CVE-2002-0651", value:TRUE);
}
