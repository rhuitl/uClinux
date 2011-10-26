#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21637);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2223", "CVE-2006-2224", "CVE-2006-2276");

 name["english"] = "RHSA-2006-0533: zebra";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated zebra packages that fix several security vulnerabilities are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  GNU Zebra is a free software that manages TCP/IP based routing protocol.

  An information disclosure flaw was found in the way GNU Zebra interprets
  RIP REQUEST packets. RIPd in GNU Zebra will respond to RIP REQUEST packets
  for RIP versions that have been disabled or that have authentication
  enabled, allowing a remote attacker to acquire information about the local
  network. (CVE-2006-2223)

  A route injection flaw was found in the way GNU Zebra interprets RIPv1
  RESPONSE packets when RIPv2 authentication is enabled. It is possible for a
  remote attacker to inject arbitrary route information into the RIPd routing
  tables. This issue does not affect GNU Zebra configurations where only
  RIPv2 is specified. (CVE-2006-2224)

  A denial of service flaw was found in GNU Zebra\'s telnet interface. If an
  attacker is able to connect to the GNU Zebra telnet interface, it is
  possible to cause GNU Zebra to consume vast quantities of CPU resources by
  issuing a malformed \'sh\' command. (CVE-2006-2276)

  Users of GNU Zebra should upgrade to these updated packages, which contain
  backported patches that correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0533.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the zebra packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"zebra-0.91a-11.21AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"zebra-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-2223", value:TRUE);
 set_kb_item(name:"CVE-2006-2224", value:TRUE);
 set_kb_item(name:"CVE-2006-2276", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0533", value:TRUE);
