#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18018);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1006");
 script_bugtraq_id(11591);

 name["english"] = "RHSA-2005-212: dhcp";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated dhcp package that fixes a string format issue is now available
  for Red Hat Enterprise Linux 2.1.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The dhcp package provides the ISC Dynamic Host Configuration Protocol
  (DHCP) server and relay agent, dhcpd. DHCP is a protocol that allows
  devices to get their own network configuration information from a server.

  A bug was found in the way dhcpd logs error messages. A malicious DNS
  server could send a carefully crafted DNS reply and cause dhcpd to crash or
  possibly execute arbitrary code. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2005-0446 to this issue.

  All users of dhcp should upgrade to this updated package, which contains a
  backported patch and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-212.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the dhcp packages";
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
if ( rpm_check( reference:"dhcp-2.0pl5-9", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"dhcp-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-1006", value:TRUE);
}

set_kb_item(name:"RHSA-2005-212", value:TRUE);
