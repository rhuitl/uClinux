#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12392);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0194", "CVE-2003-0145");

 name["english"] = "RHSA-2003-151: arpwatch";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated tcpdump packages that fix an infinite loop vulnerability and drop
  privileges on startup are now available.

  Tcpdump is a command-line tool for monitoring network traffic.

  A vulnerability exists in tcpdump before 3.7.2 and is related to an
  inability to handle unknown RADIUS attributes properly. This vulnerability
  allows remote attackers to cause a denial of service (infinite loop).

  The Red Hat tcpdump packages advertise that, by default, tcpdump will drop
  privileges to user \'pcap\'. Due to a compilation error this did not
  happen, and tcpdump would run as root unless the \'-U\' flag was specified.

  Users of tcpdump are advised to upgrade to these errata packages, which
  contain a patch correcting the RADIUS issue and are compiled so that by
  default tcpdump will drop privileges to the \'pcap\' user.




Solution : http://rhn.redhat.com/errata/RHSA-2003-151.html
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
if ( rpm_check( reference:"arpwatch-2.1a11-12.2.1AS.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap-0.6.2-12.2.1AS.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-12.2.1AS.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"arpwatch-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0194", value:TRUE);
 set_kb_item(name:"CVE-2003-0145", value:TRUE);
}

set_kb_item(name:"RHSA-2003-151", value:TRUE);
