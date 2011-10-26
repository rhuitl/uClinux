#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19988);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1740", "CVE-2005-2177");

 name["english"] = "RHSA-2005-395: net";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated net-snmp packages that fix two security issues and various bugs
  are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  SNMP (Simple Network Management Protocol) is a protocol used for network
  management.

  A denial of service bug was found in the way net-snmp uses network stream
  protocols. It is possible for a remote attacker to send a net-snmp agent a
  specially crafted packet that will crash the agent. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-2177 to this issue.

  An insecure temporary file usage bug was found in net-snmp\'s fixproc
  command. It is possible for a local user to modify the content of temporary
  files used by fixproc that can lead to arbitrary command execution. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2005-1740 to this issue.

  Additionally, the following bugs have been fixed:
  - The lmSensors are correctly recognized, snmp deamon no longer segfaults
  - The larger swap partition sizes are correctly reported
  - Querying hrSWInstalledLastUpdateTime no longer crashes the snmp deamon
  - Fixed error building ASN.1 representation
  - The 64-bit network counters correctly wrap
  - Large file systems are correctly handled
  - Snmptrapd initscript correctly reads options from its configuration
  file /etc/snmp/snmptrapd.options
  - Snmp deamon no longer crashes when restarted using the agentX
  protocol
  - snmp daemon now reports gigabit Ethernet speeds correctly
  - MAC adresses are shown when requested instead of IP adresses

  All users of net-snmp should upgrade to these updated packages, which
  resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-395.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the net packages";
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
if ( rpm_check( reference:"net-snmp-5.1.2-11.EL4.6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-devel-5.1.2-11.EL4.6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-libs-5.1.2-11.EL4.6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-perl-5.1.2-11.EL4.6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-utils-5.1.2-11.EL4.6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"net-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1740", value:TRUE);
 set_kb_item(name:"CVE-2005-2177", value:TRUE);
}

set_kb_item(name:"RHSA-2005-395", value:TRUE);
