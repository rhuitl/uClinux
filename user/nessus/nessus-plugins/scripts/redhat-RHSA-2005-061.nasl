#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16384);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0094", "CVE-2005-0095", "CVE-2005-0096", "CVE-2005-0097", "CVE-2005-0173", "CVE-2005-0174", "CVE-2005-0175", "CVE-2005-0211", "CVE-2005-0241");

 name["english"] = "RHSA-2005-061: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
An updated Squid package that fixes several security issues is now
available.

Squid is a full-featured Web proxy cache.

A buffer overflow flaw was found in the Gopher relay parser. This bug
could allow a remote Gopher server to crash the Squid proxy that reads data
from it. Although Gopher servers are now quite rare, a malicious web page
(for example) could redirect or contain a frame pointing to an attacker\'s
malicious gopher server. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0094 to this issue.

An integer overflow flaw was found in the WCCP message parser. It is
possible to crash the Squid server if an attacker is able to send a
malformed WCCP message with a spoofed source address matching Squid\'s
"home router". The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0095 to this issue.

A memory leak was found in the NTLM fakeauth_auth helper. It is possible
that an attacker could place the Squid server under high load, causing the
NTML fakeauth_auth helper to consume a large amount of memory, resulting in
a denial of service. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0096 to this issue.

Other security issues have been fixed too (see the advisory for full
details)

Users of Squid should upgrade to this updated package, which contains
backported patches, and is not vulnerable to these issues.



Solution : http://rhn.redhat.com/errata/RHSA-2005-061.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"squid-2.4.STABLE7-1.21as.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE3-6.3E.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"squid-", release:"RHEL2.1") )
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
if ( rpm_exists(rpm:"squid-", release:"RHEL3") )
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

set_kb_item(name:"RHSA-2005-061", value:TRUE);
