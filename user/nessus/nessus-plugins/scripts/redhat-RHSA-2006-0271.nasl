#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21180);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-4744", "CVE-2006-1354");

 name["english"] = "RHSA-2006-0271: freeradius";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated freeradius packages that fix an authentication weakness are now
  available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  FreeRADIUS is a high-performance and highly configurable free RADIUS server
  designed to allow centralized authentication and authorization for a network.

  A bug was found in the way FreeRADIUS authenticates users via the MSCHAP V2
  protocol. It is possible for a remote attacker to authenticate as a victim
  by sending a malformed MSCHAP V2 login request to the FreeRADIUS server.
  (CVE-2006-1354)

  Please note that FreeRADIUS installations not using the MSCHAP V2 protocol
  for authentication are not vulnerable to this issue.

  A bug was also found in the way FreeRADIUS logs SQL errors from the
  sql_unixodbc module. It may be possible for an attacker to cause FreeRADIUS
  to crash or execute arbitrary code if they are able to manipulate the SQL
  database FreeRADIUS is connecting to. (CVE-2006-4744)

  Users of FreeRADIUS should update to these erratum packages, which contain
  backported patches and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0271.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the freeradius packages";
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
if ( rpm_check( reference:"freeradius-1.0.1-2.RHEL3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freeradius-1.0.1-3.RHEL4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freeradius-mysql-1.0.1-3.RHEL4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freeradius-postgresql-1.0.1-3.RHEL4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freeradius-unixODBC-1.0.1-3.RHEL4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"freeradius-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-4744", value:TRUE);
 set_kb_item(name:"CVE-2006-1354", value:TRUE);
}
if ( rpm_exists(rpm:"freeradius-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-4744", value:TRUE);
 set_kb_item(name:"CVE-2006-1354", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0271", value:TRUE);
