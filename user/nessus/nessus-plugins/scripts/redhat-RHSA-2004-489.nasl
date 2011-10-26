#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16016);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0977");

 name["english"] = "RHSA-2004-489: rh";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated rh-postgresql packages that fix various bugs are now available.

  PostgreSQL is an advanced Object-Relational database management system
  (DBMS) that supports almost all SQL constructs (including transactions,
  subselects, and user-defined types and functions).

  Trustix has identified improper temporary file usage in the
  make_oidjoins_check script. It is possible that an attacker could
  overwrite arbitrary file contents as the user running the
  make_oidjoins_check script. This script has been removed from the RPM file
  since it has no use to ordinary users. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2004-0977 to
  this issue.

  Additionally, the following non-security issues have been addressed:

  - Fixed a low probability risk for loss of recently committed transactions.

  - Fixed a low probability risk for loss of older data due to failure to
  update transaction status.

  - A lock file problem that sometimes prevented automatic restart after a
  system crash has been fixed.

  All users of rh-postgresql should upgrade to these updated packages, which
  resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-489.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the rh packages";
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
if ( rpm_check( reference:"rh-postgresql-7.3.8-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-contrib-7.3.8-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-devel-7.3.8-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-docs-7.3.8-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-jdbc-7.3.8-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-libs-7.3.8-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-pl-7.3.8-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-python-7.3.8-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-server-7.3.8-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-tcl-7.3.8-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-test-7.3.8-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"rh-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0977", value:TRUE);
}

set_kb_item(name:"RHSA-2004-489", value:TRUE);
