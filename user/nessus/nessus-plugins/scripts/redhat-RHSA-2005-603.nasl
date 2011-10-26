#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19331);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1848");

 name["english"] = "RHSA-2005-603: dhcpcd";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated dhcpcd package that fixes a denial of service issue is
  now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The dhcpcd package includes a DHCP client daemon.

  An out of bounds memory read bug was found in dhcpcd. A malicious user on
  the local network could send a specially crafted DHCP packet to the client
  causing it to crash. The Common Vulnerabilities and Exposures project
  assigned the name CVE-2005-1848 to this issue.

  Users of dhcpcd should update to this erratum package, which contains a
  patch that resolves this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-603.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the dhcpcd packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"dhcpcd-1.3.20pl0-2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"dhcpcd-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-1848", value:TRUE);
}

set_kb_item(name:"RHSA-2005-603", value:TRUE);
