#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12432);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0856");

 name["english"] = "RHSA-2003-317: iproute";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated iproute packages that close a locally-exploitable denial of service
  vulnerability are now available.

  The iproute package contains advanced IP routing and network device
  configuration tools.

  Herbert Xu reported that iproute can accept spoofed messages sent on the
  kernel netlink interface by other users on the local machine. This could
  lead to a local denial of service attack. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2003-0856 to
  this issue.

  Users of iproute should upgrade to these erratum packages, which contain a
  patch that checks that netlink messages actually came from the kernel.




Solution : http://rhn.redhat.com/errata/RHSA-2003-317.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the iproute packages";
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
if ( rpm_check( reference:"iproute-2.4.7-7.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"iproute-2.4.7-11.30E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"iproute-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0856", value:TRUE);
}
if ( rpm_exists(rpm:"iproute-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-0856", value:TRUE);
}

set_kb_item(name:"RHSA-2003-317", value:TRUE);
