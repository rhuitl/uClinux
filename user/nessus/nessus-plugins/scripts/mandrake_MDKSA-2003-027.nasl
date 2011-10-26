#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:027
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14011);
 script_bugtraq_id(6213);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1350", "CVE-2003-0093", "CVE-2003-0108", "CVE-2003-0145");
 
 name["english"] = "MDKSA-2003:027: tcpdump";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:027 (tcpdump).


A vulnerability was discovered by Andrew Griffiths and iDEFENSE Labs in the
tcpdump program. By sending a specially crafted network packet, an attacker is
able to to cause tcpdump to enter an infinite loop. In addition, the tcpdump
developers found a potential infinite loop when tcpdump parses malformed BGP
packets. A buffer overflow was also discovered that can be exploited with
certain malformed NFS packets.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:027
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tcpdump package";
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
if ( rpm_check( reference:"libpcap0-0.7.2-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap0-devel-0.7.2-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.7.2-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap0-0.7.2-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap0-devel-0.7.2-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.7.2-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap0-0.7.2-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap0-devel-0.7.2-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.7.2-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"tcpdump-", release:"MDK8.1")
 || rpm_exists(rpm:"tcpdump-", release:"MDK8.2")
 || rpm_exists(rpm:"tcpdump-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1350", value:TRUE);
 set_kb_item(name:"CVE-2003-0093", value:TRUE);
 set_kb_item(name:"CVE-2003-0108", value:TRUE);
 set_kb_item(name:"CVE-2003-0145", value:TRUE);
}
