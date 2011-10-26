#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12635);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0010");
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2002-0400", "CVE-2002-0651");

 name["english"] = "RHSA-2002-119: bind";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Version 9 of ISC BIND, prior to version 9.2.1, contained a denial of
  service (DoS) attack vulnerability. Various versions of the ISC BIND
  resolver libraries are vulnerable to a buffer overflow attack.

  ISC BIND (Berkeley Internet Name Domain) is an implementation of the DNS
  (Domain Name System) protocols. BIND includes a DNS server (named) --
  which resolves hostnames to IP addresses, a resolver library
  (routines for applications to use when interfacing with DNS), and
  various tools.

  Versions of BIND 9 prior to 9.2.1 have a bug that causes certain requests
  to the BIND name server to fail an internal consistency check, causing the
  name server to stop responding to requests. This can be used by a remote
  attacker to cause a denial of service (DoS) attack against name servers.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2002-0400 to this issue.

  A buffer overflow vulnerability exists in multiple implementations of DNS
  resolver libraries. Applications that utilize vulnerable DNS resolver
  libraries may be affected. A remote attacker who is able to send malicious
  DNS responses could potentially exploit this vulnerability to execute
  arbitrary code or cause a denial of service (DoS) attack on a vulnerable
  system. Red Hat Linux does not ship with any applications or libraries that
  link against the BIND resolver libraries; however, third party code may be
  affected. (CVE-2002-0651)

  Red Hat Linux Advanced Server shipped with a version of ISC BIND vulnerable
  to both of these issues. All users of BIND are advised to upgrade to the
  errata packages containing BIND 9.2.1 which contains backported patches
  that correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2002-119.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the bind packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"bind-9.2.1-1.7x.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind-devel-9.2.1-1.7x.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind-utils-9.2.1-1.7x.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"bind-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0400", value:TRUE);
 set_kb_item(name:"CVE-2002-0651", value:TRUE);
}

set_kb_item(name:"RHSA-2002-119", value:TRUE);
