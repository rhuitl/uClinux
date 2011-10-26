#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:006
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16372);
 script_version ("$Revision: 1.2 $");
 if ( NASL_LEVEL >= 2200 ) script_cve_id("CVE-2005-0094", "CVE-2005-0095", "CVE-2005-0096", "CVE-2005-0097", "CVE-2005-0173", "CVE-2005-0174", "CVE-2005-0175", "CVE-2005-0211", "CVE-2005-0241");
 
 name["english"] = "SUSE-SA:2005:006: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:006 (squid).


Squid is a feature-rich web-proxy with support for various web-related
protocols.
The last two squid updates from February the 1st and 10th fix several
vulnerabilities. The impact of them range from remote denial-of-service
over cache poisoning to possible remote command execution.
Due to the hugh amount of bugs the vulnerabilities are just summarized
here.

CVE-2005-0094
A buffer overflow in the Gopher responses parser leads
to memory corruption and usually crash squid.

CVE-2005-0095
An integer overflow in the receiver of WCCP (Web Cache
Communication Protocol) messages can be exploited remotely
by sending a specially crafted UDP datagram to crash squid.

CVE-2005-0096
A memory leak in the NTLM fakeauth_auth helper for
Squid 2.5.STABLE7 and earlier allows remote attackers
to cause a denial-of-service due to uncontrolled memory
consumption.

CVE-2005-0097 
The NTLM component in Squid 2.5.STABLE7 and earlier allows
remote attackers to cause a crash od squid by sending a
malformed NTLM message. 

CVE-2005-0173
LDAP handles search filters very laxly. This behaviour can
be abused to log in using several variants of a login name,
possibly bypassing explicit access controls or confusing
accounting.

CVE-2005-0175 and CVE-2005-0174
Minor problems in the HTTP header parsing code that
can be used for cache poisoning.

CVE-2005-0211
A buffer overflow in the WCCP handling code in Squid 2.5
before 2.5.STABLE7 allows remote attackers to cause a
denial-of-service and possibly execute arbitrary code
by using a long WCCP packet.

CVE-2005-0241
The httpProcessReplyHeader function in Squid 2.5-STABLE7
and earlier does not properly set the debug context when
it is handling 'oversized' HTTP reply headers. The impact
is unknown.



Solution : http://www.suse.de/security/advisories/2005_06_squid.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid package";
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
if ( rpm_check( reference:"squid-2.4.STABLE7-288", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE1-106", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE3-118", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE5-42.27", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE6-6.6", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"squid-", release:"SUSE8.1")
 || rpm_exists(rpm:"squid-", release:"SUSE8.2")
 || rpm_exists(rpm:"squid-", release:"SUSE9.0")
 || rpm_exists(rpm:"squid-", release:"SUSE9.1")
 || rpm_exists(rpm:"squid-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2005-0094", value:TRUE);
 set_kb_item(name:"CVE-2005-0095", value:TRUE);
 set_kb_item(name:"CVE-2005-0096", value:TRUE);
 set_kb_item(name:"CVE-2005-0097", value:TRUE);
 set_kb_item(name:"CVE-2005-0173", value:TRUE);
 set_kb_item(name:"CVE-2005-0174", value:TRUE);
 set_kb_item(name:"CVE-2005-0175", value:TRUE);
 set_kb_item(name:"CVE-2005-0211", value:TRUE);
 set_kb_item(name:"CVE-2005-0241", value:TRUE);
}
