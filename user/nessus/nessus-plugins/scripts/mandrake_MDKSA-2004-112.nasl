#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:112
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15547);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0918");
 
 name["english"] = "MDKSA-2004:112: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:112 (squid).


iDEFENSE discovered a Denial of Service vulnerability in squid version
2.5.STABLE6 and previous. The problem is due to an ASN1 parsing error where
certain header length combinations can slip through the validations performed by
the ASN1 parser, leading to the server assuming there is heap corruption or some
other exceptional condition, and closing all current connections then
restarting.
Squid 2.5.STABLE7 has been released to address this issue; the provided packages
are patched to fix the issue.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:112
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid package";
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
if ( rpm_check( reference:"squid-2.5.STABLE4-2.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE3-3.4.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"squid-", release:"MDK10.0")
 || rpm_exists(rpm:"squid-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0918", value:TRUE);
}
