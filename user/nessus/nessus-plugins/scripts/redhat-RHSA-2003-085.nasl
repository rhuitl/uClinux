#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12375);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2003-0108");

 name["english"] = "RHSA-2003-085: arpwatch";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated tcpdump packages are available to fix a denial of service
  vulnerability in tcpdump.

  [Updated 12 March 2003]
  Added packages for Red Hat Enterprise Linux ES and Red Hat Enterprise
  Linux WS

  Tcpdump is a command-line tool for monitoring network traffic.

  The ISAKMP parser in tcpdump 3.6 through 3.7.1 allows remote attackers to
  cause a denial of service (CPU consumption) via a certain malformed ISAKMP
  packet to UDP port 500, which causes tcpdump to enter an infinite loop.

  Users of tcpdump are advised to upgrade to these errata packages which
  contain a patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-085.html
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
if ( rpm_check( reference:"arpwatch-2.1a11-12.2.1AS.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap-0.6.2-12.2.1AS.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-12.2.1AS.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"arpwatch-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0108", value:TRUE);
}

set_kb_item(name:"RHSA-2003-085", value:TRUE);
