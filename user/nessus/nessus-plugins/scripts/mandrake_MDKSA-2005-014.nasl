#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:014
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16242);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0094", "CVE-2005-0095");
 
 name["english"] = "MDKSA-2005:014: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:014 (squid).



'infamous41md' discovered two vulnerabilities in the squid proxy cache server.
The first is a buffer overflow in the Gopher response parser which leads to
memory corruption and would usually crash squid (CVE-2005-0094). The second is
an integer overflow in the receiver of WCCP (Web Cache Communication Protocol)
messages. An attacker could send a specially crafted UDP datagram that would
cause squid to crash (CVE-2005-0095).

The updated packages have been patched to prevent these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:014
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid package";
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
if ( rpm_check( reference:"squid-2.5.STABLE4-2.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE6-2.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE3-3.5.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"squid-", release:"MDK10.0")
 || rpm_exists(rpm:"squid-", release:"MDK10.1")
 || rpm_exists(rpm:"squid-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2005-0094", value:TRUE);
 set_kb_item(name:"CVE-2005-0095", value:TRUE);
}
