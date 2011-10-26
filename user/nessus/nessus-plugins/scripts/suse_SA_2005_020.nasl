#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:020
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17671);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0398");
 
 name["english"] = "SUSE-SA:2005:020: ipsec-tools";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:020 (ipsec-tools).


Racoon is a ISAKMP key management daemon used in IPsec setups.

Sebastian Krahmer of the SUSE Security Team audited the daemon and
found that it handles certain ISAKMP messages in a slightly wrong way,
so that remote attackers can crash it via malformed ISAKMP packages.

This update fixes this problem.

This is tracked by the Mitre CVE ID CVE-2005-0398.



Solution : http://www.suse.de/security/advisories/2005_20_ipsec_tools.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ipsec-tools package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ipsec-tools-0.3.3-1.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ipsec-tools-0.4rc1-3.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ipsec-tools-", release:"SUSE9.1")
 || rpm_exists(rpm:"ipsec-tools-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2005-0398", value:TRUE);
}
