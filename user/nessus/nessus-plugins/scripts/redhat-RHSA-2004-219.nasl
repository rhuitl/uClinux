#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12498);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0183", "CVE-2004-0184");

 name["english"] = "RHSA-2004-219: arpwatch";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated tcpdump, libpcap, and arpwatch packages fix vulnerabilities in
  ISAKMP parsing.

  Tcpdump is a command-line tool for monitoring network traffic.

  Tcpdump v3.8.1 and earlier versions contained multiple flaws in the
  packet display functions for the ISAKMP protocol. Upon receiving
  specially crafted ISAKMP packets, TCPDUMP would try to read beyond
  the end of the packet capture buffer and subsequently crash.

  Users of tcpdump are advised to upgrade to these erratum packages, which
  contain backported security patches and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-219.html
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
if ( rpm_check( reference:"arpwatch-2.1a11-12.2.1AS.6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap-0.6.2-12.2.1AS.6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-12.2.1AS.6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap-0.7.2-7.E3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.7.2-7.E3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"arpwatch-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0183", value:TRUE);
 set_kb_item(name:"CVE-2004-0184", value:TRUE);
}
if ( rpm_exists(rpm:"arpwatch-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0183", value:TRUE);
 set_kb_item(name:"CVE-2004-0184", value:TRUE);
}

set_kb_item(name:"RHSA-2004-219", value:TRUE);
