#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18557);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1454", "CVE-2005-1455");

 name["english"] = "RHSA-2005-524: freeradius";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated freeradius packages that fix a buffer overflow and possible SQL
  injection attacks in the sql module are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  FreeRADIUS is a high-performance and highly configurable free RADIUS server
  designed to allow centralized authentication and authorization for a network.

  A buffer overflow bug was found in the way FreeRADIUS escapes data in an
  SQL query. An attacker may be able to crash FreeRADIUS if they cause
  FreeRADIUS to escape a string containing three or less characters. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2005-1454 to this issue.

  Additionally a bug was found in the way FreeRADIUS escapes SQL data. It is
  possible that an authenticated user could execute arbitrary SQL queries by
  sending a specially crafted request to FreeRADIUS. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-1455 to this issue.

  Users of FreeRADIUS should update to these erratum packages, which contain
  backported patches and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-524.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the freeradius packages";
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
if ( rpm_check( reference:"freeradius-1.0.1-1.1.RHEL3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freeradius-1.0.1-3.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freeradius-mysql-1.0.1-3.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freeradius-postgresql-1.0.1-3.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freeradius-unixODBC-1.0.1-3.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"freeradius-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-1454", value:TRUE);
 set_kb_item(name:"CVE-2005-1455", value:TRUE);
}
if ( rpm_exists(rpm:"freeradius-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1454", value:TRUE);
 set_kb_item(name:"CVE-2005-1455", value:TRUE);
}

set_kb_item(name:"RHSA-2005-524", value:TRUE);
