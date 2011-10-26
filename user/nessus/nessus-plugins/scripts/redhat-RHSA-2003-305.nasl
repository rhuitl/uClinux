#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12427);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0795", "CVE-2003-0858");

 name["english"] = "RHSA-2003-305: zebra";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated zebra packages that close a locally-exploitable and a
  remotely-exploitable denial of service vulnerability are now available.

  Zebra an open source implementation of TCP/IP routing software.

  Jonny Robertson reported that Zebra can be remotely crashed if a Zebra
  password has been enabled and a remote attacker can connect to the Zebra
  telnet management port. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2003-0795 to this issue.

  Herbert Xu reported that Zebra can accept spoofed messages sent on the
  kernel netlink interface by other users on the local machine. This could
  lead to a local denial of service attack. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2003-0858 to
  this issue.

  Users of Zebra should upgrade to these erratum packages, which contain
  a patch preventing Zebra from crashing when it receives a telnet option
  delimiter without any option data, and a patch that checks that netlink
  messages actually came from the kernel.




Solution : http://rhn.redhat.com/errata/RHSA-2003-305.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the zebra packages";
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
if ( rpm_check( reference:"zebra-0.91a-10.21AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"zebra-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0795", value:TRUE);
 set_kb_item(name:"CVE-2003-0858", value:TRUE);
}

set_kb_item(name:"RHSA-2003-305", value:TRUE);
