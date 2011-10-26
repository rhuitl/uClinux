#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21595);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0591", "CVE-2006-2313", "CVE-2006-2314");

 name["english"] = "RHSA-2006-0526: rh-postgres";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated postgresql packages that fix several security vulnerabilities are
  now available for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  PostgreSQL is an advanced Object-Relational database management system
  (DBMS).

  A bug was found in the way PostgreSQL\'s PQescapeString function escapes
  strings when operating in a multibyte character encoding. It is possible
  for an attacker to provide an application a carefully crafted string
  containing invalidly-encoded characters, which may be improperly escaped,
  allowing the attacker to inject malicious SQL. While this update fixes how
  PQescapeString operates, the PostgreSQL server has also been modified to
  prevent such an attack occurring through unpatched clients.
  (CVE-2006-2313, CVE-2006-2314). More details about this issue are
  available in the linked PostgreSQL technical documentation.

  An integer signedness bug was found in the way PostgreSQL generated
  password salts. The actual salt size is only half the size of the expected
  salt, making the process of brute forcing password hashes slightly easier.
  This update will not strengthen already existing passwords, but all newly
  assigned passwords will have the proper salt length. (CVE-2006-0591)

  Users of PostgreSQL should upgrade to these updated packages containing
  PostgreSQL version 7.4.13, which corrects these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0526.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the rh packages";
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
if ( rpm_check( reference:"rh-postgresql-7.3.15-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-contrib-7.3.15-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-devel-7.3.15-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-docs-7.3.15-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-jdbc-7.3.15-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-libs-7.3.15-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-pl-7.3.15-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-python-7.3.15-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-server-7.3.15-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-tcl-7.3.15-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-test-7.3.15-2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-7.4.13-2.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-7.4.13-2.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-7.4.13-2.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-7.4.13-2.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-jdbc-7.4.13-2.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-7.4.13-2.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-7.4.13-2.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-python-7.4.13-2.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-7.4.13-2.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-tcl-7.4.13-2.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-test-7.4.13-2.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"rh-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-0591", value:TRUE);
 set_kb_item(name:"CVE-2006-2313", value:TRUE);
 set_kb_item(name:"CVE-2006-2314", value:TRUE);
}
if ( rpm_exists(rpm:"rh-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-0591", value:TRUE);
 set_kb_item(name:"CVE-2006-2313", value:TRUE);
 set_kb_item(name:"CVE-2006-2314", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0526", value:TRUE);
