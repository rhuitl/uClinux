#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20399);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3656");

 name["english"] = "RHSA-2006-0164: mod_auth_pgsql";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mod_auth_pgsql packages that fix format string security issues are
  now available for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The mod_auth_pgsql package is an httpd module that allows user
  authentication against information stored in a PostgreSQL database.

  Several format string flaws were found in the way mod_auth_pgsql logs
  information. It may be possible for a remote attacker to execute arbitrary
  code as the \'apache\' user if mod_auth_pgsql is used for user
  authentication. The Common Vulnerabilities and Exposures project assigned
  the name CVE-2005-3656 to this issue.

  Please note that this issue only affects servers which have mod_auth_pgsql
  installed and configured to perform user authentication against a
  PostgreSQL database.

  All users of mod_auth_pgsql should upgrade to these updated packages, which
  contain a backported patch to resolve this issue.

  This issue does not affect the mod_auth_pgsql package supplied with Red Hat
  Enterprise Linux 2.1.

  Red Hat would like to thank iDefense for reporting this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0164.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mod_auth_pgsql packages";
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
if ( rpm_check( reference:"mod_auth_pgsql-2.0.1-4.ent.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_auth_pgsql-2.0.1-7.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mod_auth_pgsql-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-3656", value:TRUE);
}
if ( rpm_exists(rpm:"mod_auth_pgsql-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-3656", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0164", value:TRUE);
