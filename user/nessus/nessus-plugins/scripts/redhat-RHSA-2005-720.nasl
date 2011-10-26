#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19413);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2177");

 name["english"] = "RHSA-2005-720: ucd";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated ucd-snmp packages that a security issue are now available for Red
  Hat Enterprise Linux 2.1.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  SNMP (Simple Network Management Protocol) is a protocol used for network
  management.

  A denial of service bug was found in the way ucd-snmp uses network stream
  protocols. A remote attacker could send a ucd-snmp agent a specially
  crafted packet which will cause the agent to crash. The Common
  Vulnerabilities and Exposures project assigned the name CVE-2005-2177 to
  this issue.

  All users of ucd-snmp should upgrade to these updated packages, which
  contain a backported patch to resolve this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-720.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ucd packages";
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
if ( rpm_check( reference:"ucd-snmp-4.2.5-8.AS21.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ucd-snmp-devel-4.2.5-8.AS21.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ucd-snmp-utils-4.2.5-8.AS21.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ucd-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-2177", value:TRUE);
}

set_kb_item(name:"RHSA-2005-720", value:TRUE);
