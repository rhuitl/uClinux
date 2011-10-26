#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12448);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0008");
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0989", "CVE-2004-0055", "CVE-2004-0057");

 name["english"] = "RHSA-2004-008: arpwatch";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated tcpdump, libpcap, and arpwatch packages fix vulnerabilities in
  ISAKMP and RADIUS parsing.

  [Updated 15 Jan 2004]
  Updated the text description to better describe the vulnerabilities found
  by Jonathan Heusser and give them CVE names.

  Tcpdump is a command-line tool for monitoring network traffic.

  George Bakos discovered flaws in the ISAKMP decoding routines of tcpdump
  versions prior to 3.8.1. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2003-0989 to this issue.

  Jonathan Heusser discovered an additional flaw in the ISAKMP decoding
  routines for tcpdump 3.8.1 and earlier. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2004-0057 to
  this issue.

  Jonathan Heusser discovered a flaw in the print_attr_string function in the
  RADIUS decoding routines for tcpdump 3.8.1 and earlier. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0055 to this issue.

  Remote attackers could potentially exploit these issues by sending
  carefully-crafted packets to a victim. If the victim uses tcpdump, these
  pakets could result in a denial of service, or possibly execute arbitrary
  code as the \'pcap\' user.

  Users of tcpdump are advised to upgrade to these erratum packages, which
  contain backported security patches and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-008.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the arpwatch packages";
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
if ( rpm_check( reference:"arpwatch-2.1a11-12.2.1AS.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap-0.6.2-12.2.1AS.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-12.2.1AS.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap-0.7.2-7.E3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.7.2-7.E3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"arpwatch-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0989", value:TRUE);
 set_kb_item(name:"CVE-2004-0055", value:TRUE);
 set_kb_item(name:"CVE-2004-0057", value:TRUE);
}
if ( rpm_exists(rpm:"arpwatch-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-0989", value:TRUE);
 set_kb_item(name:"CVE-2004-0055", value:TRUE);
 set_kb_item(name:"CVE-2004-0057", value:TRUE);
}

set_kb_item(name:"RHSA-2004-008", value:TRUE);
