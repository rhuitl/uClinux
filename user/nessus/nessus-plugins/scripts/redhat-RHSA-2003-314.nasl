#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12430);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0901");

 name["english"] = "RHSA-2003-314: postgresql";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated PostgreSQL packages that correct a buffer overflow in the to_ascii
  routines are now available.

  PostgreSQL is an advanced Object-Relational database management system
  (DBMS).

  Two bugs that can lead to buffer overflows have been found in the
  PostgreSQL abstract data type to ASCII conversion routines. A remote
  attacker who is able to influence the data passed to the to_ascii functions
  may be able to execute arbitrary code in the context of the PostgreSQL
  server. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2003-0901 to these issues.

  In addition, a bug that can lead to leaks has been found in the string to
  timestamp abstract data type conversion routine. If the input string to
  the to_timestamp() routine is shorter than what the template string is
  expecting, the routine will run off the end of the input string, resulting
  in a leak and unstable behaviour.

  Users of PostgreSQL are advised to upgrade to these erratum packages, which
  contain a backported patch that corrects these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2003-314.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the postgresql packages";
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
if ( rpm_check( reference:"postgresql-7.1.3-5.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-7.1.3-5.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-7.1.3-5.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-7.1.3-5.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-jdbc-7.1.3-5.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-7.1.3-5.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-odbc-7.1.3-5.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-perl-7.1.3-5.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-python-7.1.3-5.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-7.1.3-5.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-tcl-7.1.3-5.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-test-7.1.3-5.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-tk-7.1.3-5.rhel2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"postgresql-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0901", value:TRUE);
}

set_kb_item(name:"RHSA-2003-314", value:TRUE);
