#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18408);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1409", "CVE-2005-1410");

 name["english"] = "RHSA-2005-433: rh";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated postgresql packages that fix several security vulnerabilities and
  risks of data loss are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.


  All users of PostgreSQL are advised to upgrade to these updated packages
  and to apply the recommended manual corrections to existing databases.




Solution : http://rhn.redhat.com/errata/RHSA-2005-433.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the rh packages";
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
if ( rpm_check( reference:"rh-postgresql-7.3.10-1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-contrib-7.3.10-1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-devel-7.3.10-1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-docs-7.3.10-1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-jdbc-7.3.10-1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-libs-7.3.10-1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-pl-7.3.10-1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-python-7.3.10-1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-server-7.3.10-1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-tcl-7.3.10-1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-test-7.3.10-1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-7.4.8-1.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-7.4.8-1.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-7.4.8-1.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-7.4.8-1.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-jdbc-7.4.8-1.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-7.4.8-1.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-7.4.8-1.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-python-7.4.8-1.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-7.4.8-1.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-tcl-7.4.8-1.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-test-7.4.8-1.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"rh-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-1409", value:TRUE);
 set_kb_item(name:"CVE-2005-1410", value:TRUE);
}
if ( rpm_exists(rpm:"rh-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1409", value:TRUE);
 set_kb_item(name:"CVE-2005-1410", value:TRUE);
}

set_kb_item(name:"RHSA-2005-433", value:TRUE);
