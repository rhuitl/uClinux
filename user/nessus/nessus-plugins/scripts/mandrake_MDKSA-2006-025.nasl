#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:025
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20819);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-1740", "CVE-2005-2177");
 
 name["english"] = "MDKSA-2006:025: net-snmp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:025 (net-snmp).



The fixproc application in Net-SNMP creates temporary files with predictable
file names which could allow a malicious local attacker to change the contents
of the temporary file by exploiting a race condition, which could possibly lead
to the execution of arbitrary code. As well, a local attacker could create
symbolic links in the /tmp directory that point to a valid file that would then
be overwritten when fixproc is executed (CVE-2005-1740). A remote Denial of
Service vulnerability was also discovered in the SNMP library that could be
exploited by a malicious SNMP server to crash the agent, if the agent uses TCP
sockets for communication (CVE-2005-2177). The updated packages have been
patched to correct these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:025
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the net-snmp package";
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
if ( rpm_check( reference:"libnet-snmp5-5.1.2-6.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnet-snmp5-devel-5.1.2-6.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnet-snmp5-static-devel-5.1.2-6.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-5.1.2-6.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-mibs-5.1.2-6.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-trapd-5.1.2-6.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-utils-5.1.2-6.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-NetSNMP-5.1.2-6.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnet-snmp5-5.2.1-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnet-snmp5-devel-5.2.1-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnet-snmp5-static-devel-5.2.1-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-5.2.1-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-mibs-5.2.1-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-trapd-5.2.1-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-utils-5.2.1-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-NetSNMP-5.2.1-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"net-snmp-", release:"MDK10.1")
 || rpm_exists(rpm:"net-snmp-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1740", value:TRUE);
 set_kb_item(name:"CVE-2005-2177", value:TRUE);
}
