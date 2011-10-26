#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17129);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0227", "CVE-2005-0245", "CVE-2005-0247");

 name["english"] = "RHSA-2005-150: postgresql";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated PostgreSQL packages to fix various security flaws are now available
  for Red Hat Enterprise Linux 2.1AS.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  PostgreSQL is an advanced Object-Relational database management system
  (DBMS).

  A flaw in the LOAD command in PostgreSQL was discovered. A local user
  could use this flaw to load arbitrary shared libraries and therefore
  execute arbitrary code, gaining the privileges of the PostgreSQL server.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-0227 to this issue.

  Multiple buffer overflows were found in PL/PgSQL. A database user who has
  permissions to create plpgsql functions could trigger this flaw which could
  lead to arbitrary code execution, gaining the privileges of the PostgreSQL
  server. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the names CVE-2005-0245 and CVE-2005-0247 to these issues.

  Users of PostgreSQL are advised to update to these erratum packages which
  are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-150.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the postgresql packages";
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
if ( rpm_check( reference:"postgresql-7.1.3-6.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-7.1.3-6.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-7.1.3-6.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-7.1.3-6.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-jdbc-7.1.3-6.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-7.1.3-6.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-odbc-7.1.3-6.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-perl-7.1.3-6.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-python-7.1.3-6.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-7.1.3-6.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-tcl-7.1.3-6.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-test-7.1.3-6.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-tk-7.1.3-6.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"postgresql-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0227", value:TRUE);
 set_kb_item(name:"CVE-2005-0245", value:TRUE);
 set_kb_item(name:"CVE-2005-0247", value:TRUE);
}

set_kb_item(name:"RHSA-2005-150", value:TRUE);
