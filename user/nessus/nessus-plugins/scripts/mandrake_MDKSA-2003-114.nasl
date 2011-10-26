#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:114
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14096);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0925", "CVE-2003-0926", "CVE-2003-0927");
 
 name["english"] = "MDKSA-2003:114: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:114 (ethereal).


A number of vulnerabilities were discovered in ethereal that, if exploited,
could be used to make ethereal crash or run arbitrary code by injecting
malicious malformed packets onto the wire or by convincing someone to read a
malformed packet trace file.
A buffer overflow allows attackers to cause a DoS (Denial of Service) and
possibly execute arbitrary code using a malformed GTP MSISDN string
(CVE-2003-0925).
Likewise, a DoS can be caused by using malformed ISAKMP or MEGACO packets
(CVE-2003-0926).
Finally, a heap-based buffer overflow allows attackers to cause a DoS or execute
arbitrary code using the SOCKS dissector (CVE-2003-0927).
All three vulnerabilities affect all versions of Ethereal up to and including
0.9.15. This update provides 0.9.16 which corrects all of these issues. Also
note that each vulnerability can be exploited by a remote attacker.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:114
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
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
if ( rpm_check( reference:"ethereal-0.9.16-2.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.9.16-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK9.1")
 || rpm_exists(rpm:"ethereal-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0925", value:TRUE);
 set_kb_item(name:"CVE-2003-0926", value:TRUE);
 set_kb_item(name:"CVE-2003-0927", value:TRUE);
}
