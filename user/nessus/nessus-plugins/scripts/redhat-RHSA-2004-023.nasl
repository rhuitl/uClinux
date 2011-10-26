#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12453);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0935");

 name["english"] = "RHSA-2004-023: net";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Net-SNMP packages are available to correct a security vulnerability
  and other bugs.

  The Net-SNMP project includes various Simple Network Management Protocol
  (SNMP) tools.

  A security issue in Net-SNMP versions before 5.0.9 could allow an existing
  user/community to gain access to data in MIB objects that were explicitly
  excluded from their view. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2003-0935 to this issue.

  Users of Net-SNMP are advised to upgrade to these errata packages containing
  Net-SNMP 5.0.9 which is not vulnerable to this issue. In addition,
  Net-SNMP 5.0.9 fixes a number of other minor bugs.




Solution : http://rhn.redhat.com/errata/RHSA-2004-023.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the net packages";
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
if ( rpm_check( reference:"net-snmp-5.0.9-2.30E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-devel-5.0.9-2.30E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-snmp-utils-5.0.9-2.30E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"net-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-0935", value:TRUE);
}

set_kb_item(name:"RHSA-2004-023", value:TRUE);
