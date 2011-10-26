#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:101
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18498);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-1267");
 
 name["english"] = "MDKSA-2005:101: tcpdump";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:101 (tcpdump).



A Denial of Service vulnerability was found in tcpdump during the processing of
certain network packages. Because of this flaw, it was possible for an attacker
to inject a carefully crafted packet onto the network which would crash a
running tcpdump session.

The updated packages have been patched to correct this problem. This problem
does not affect at least tcpdump 3.8.1 and earlier.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:101
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tcpdump package";
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
if ( rpm_check( reference:"tcpdump-3.8.3-2.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.8.3-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"tcpdump-", release:"MDK10.1")
 || rpm_exists(rpm:"tcpdump-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1267", value:TRUE);
}
