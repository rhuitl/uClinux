#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15534);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0381", "CVE-2004-0388", "CVE-2004-0457");

 name["english"] = "RHSA-2004-569: mysql";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mysql packages that fix various temporary file security issues,
  as well as a number of bugs, are now available.

  MySQL is a multi-user, multi-threaded SQL database server.

  This update fixes a number of small bugs, including some potential
  security problems associated with careless handling of temporary files.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the names CVE-2004-0381, CVE-2004-0388, and CVE-2004-0457 to these
  issues.

  A number of additional security issues that affect mysql have been
  corrected in the source package. These include CVE-2004-0835,
  CVE-2004-0836, CVE-2004-0837, and CVE-2004-0957. Red Hat Enterprise Linux
  3 does not ship with the mysql-server package and is therefore not affected
  by these issues.

  This update also allows 32-bit and 64-bit libraries to be installed
  concurrently on the same system.

  All users of mysql should upgrade to these updated packages, which resolve
  these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-569.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mysql packages";
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
if ( rpm_check( reference:"mysql-3.23.58-2.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-bench-3.23.58-2.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-3.23.58-2.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-3.23.58-2.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-3.23.58-2.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mysql-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0381", value:TRUE);
 set_kb_item(name:"CVE-2004-0388", value:TRUE);
 set_kb_item(name:"CVE-2004-0457", value:TRUE);
}

set_kb_item(name:"RHSA-2004-569", value:TRUE);
