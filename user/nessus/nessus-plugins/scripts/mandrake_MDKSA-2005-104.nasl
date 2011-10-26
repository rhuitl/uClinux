#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:104
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18561);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-1519");
 
 name["english"] = "MDKSA-2005:104: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:104 (squid).



A bug was found in the way that Squid handles DNS replies. If the port Squid
uses for DNS requests is not protected by a firewall, it is possible for a
remote attacker to spoof DNS replies, possibly redirecting a user to spoofed or
malicious content.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:104
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
if ( rpm_check( reference:"squid-2.5.STABLE9-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"squid-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1519", value:TRUE);
}
