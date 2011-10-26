#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12632);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0380");

 name["english"] = "RHSA-2002-121: arpwatch";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated tcpdump, libpcap, and arpwatch packages are available. These
  updates close a buffer overflow when handling NFS packets.

  tcpdump is a command-line tool for monitoring network traffic. Versions of
  tcpdump up to and including 3.6.2 have a buffer overflow that can be
  triggered when tracing the network by a bad NFS packet.

  We are not yet aware if this issue is fully exploitable; however, users of
  tcpdump are advised to upgrade to these errata packages which contain a
  patch for this issue.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2002-0380 to this issue. This issue was found by
  David Woodhouse of Red Hat.




Solution : http://rhn.redhat.com/errata/RHSA-2002-121.html
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
if ( rpm_check( reference:"arpwatch-2.1a11-11.2.1AS.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap-0.6.2-11.2.1AS.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-11.2.1AS.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"arpwatch-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0380", value:TRUE);
}

set_kb_item(name:"RHSA-2002-121", value:TRUE);
