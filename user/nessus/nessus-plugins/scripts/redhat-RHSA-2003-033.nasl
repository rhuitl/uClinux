#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12358);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1350", "CVE-2003-0093");

 name["english"] = "RHSA-2003-033: arpwatch";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated tcpdump, libpcap, and arpwatch packages are available to fix an
  incorrect bounds check when decoding BGP packets and a possible denial of
  service.

  Tcpdump is a command-line tool for monitoring network traffic.

  The BGP decoding routines in tcpdump before version 3.6.2 used incorrect
  bounds checking when copying data, which allows remote attackers to cause a
  denial of service and possibly execute arbitrary code (as the \'pcap\' user).

  If a UDP packet from a radius port contains 0 at the second byte tcpdump
  gets stuck in a loop that generating an infinite stream of "#0#0#0#0#0".
  This could be used as a denial of service.

  Users of tcpdump are advised to upgrade to these errata packages which
  contain patches to correct thes issues.




Solution : http://rhn.redhat.com/errata/RHSA-2003-033.html
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
if ( rpm_check( reference:"arpwatch-2.1a11-12.2.1AS.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap-0.6.2-12.2.1AS.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-12.2.1AS.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"arpwatch-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1350", value:TRUE);
 set_kb_item(name:"CVE-2003-0093", value:TRUE);
}

set_kb_item(name:"RHSA-2003-033", value:TRUE);
