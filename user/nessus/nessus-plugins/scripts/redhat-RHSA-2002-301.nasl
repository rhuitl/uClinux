#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12343);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-0972", "CVE-2002-1397", "CVE-2002-1398", "CVE-2002-1400", "CVE-2002-1401", "CVE-2002-1402");

 name["english"] = "RHSA-2002-301: postgresql";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated PostgreSQL packages are available which correct
  several minor security vulnerabilities.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  PostgreSQL is an advanced Object-Relational database management system
  (DBMS). Red Hat Linux Advanced Server 2.1 shipped with PostgreSQL version
  7.1.3 which has several security vulnerabilities.

  Buffer overflows in PostgreSQL 7.2 allow attackers to cause a denial of
  service and possibly execute arbitrary code via long arguments to the lpad
  or rpad functions. CVE-2002-0972

  Buffer overflow in the cash_words() function for PostgreSQL 7.2 and
  earlier allows local users to cause a denial of service and possibly
  execute arbitrary code via a malformed argument. CVE-2002-1397

  Buffer overflow in the date parser for PostgreSQL before 7.2.2 allows
  attackers to cause a denial of service and possibly execute arbitrary
  code via a long date string, referred to as a vulnerability "in handling
  long datetime input." CVE-2002-1398

  Heap-based buffer overflow in the repeat() function for PostgreSQL
  before 7.2.2 allows attackers to execute arbitrary code by causing
  repeat() to generate a large string. CVE-2002-1400

  Buffer overflows in circle_poly, path_encode, and path_add allow attackers
  to cause a denial of service and possibly execute arbitrary code. Note
  that these issues have been fixed in our packages and in PostgreSQL CVS,
  but are not included in PostgreSQL version 7.2.2 or 7.2.3. CVE-2002-1401

  Buffer overflows in the TZ and SET TIME ZONE enivronment variables for
  PostgreSQL 7.2.1 and earlier allow local users to cause a denial of service
  and possibly execute arbitrary code. CVE-2002-1402

  Note that these vulnerabilities are only critical on open or shared systems
  because connecting to the database is required before the vulnerabilities
  can be exploited.

  The PostgreSQL Global Development Team has released versions of PostgreSQL
  that fix these vulnerabilities, and these fixes have been isolated and
  backported into the updated 7.1.3 packages provided with this errata.
  All users of Red Hat Linux Advanced Server 2.1 who use PostgreSQL are
  advised to install these updated packages.




Solution : http://rhn.redhat.com/errata/RHSA-2002-301.html
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
if ( rpm_check( reference:"postgresql-7.1.3-4bp.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-7.1.3-4bp.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-7.1.3-4bp.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-7.1.3-4bp.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-jdbc-7.1.3-4bp.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-7.1.3-4bp.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-odbc-7.1.3-4bp.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-perl-7.1.3-4bp.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-python-7.1.3-4bp.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-7.1.3-4bp.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-tcl-7.1.3-4bp.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-tk-7.1.3-4bp.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"postgresql-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0972", value:TRUE);
 set_kb_item(name:"CVE-2002-1397", value:TRUE);
 set_kb_item(name:"CVE-2002-1398", value:TRUE);
 set_kb_item(name:"CVE-2002-1400", value:TRUE);
 set_kb_item(name:"CVE-2002-1401", value:TRUE);
 set_kb_item(name:"CVE-2002-1402", value:TRUE);
}

set_kb_item(name:"RHSA-2002-301", value:TRUE);
