#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19993);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1636");

 name["english"] = "RHSA-2005-685: mysql";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mysql packages that fix a temporary file flaw and a number of bugs
  are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
  client/server implementation consisting of a server daemon (mysqld)
  and many different client programs and libraries.

  An insecure temporary file handling bug was found in the mysql_install_db
  script. It is possible for a local user to create specially crafted files
  in /tmp which could allow them to execute arbitrary SQL commands during
  database installation. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-1636 to this issue.

  These packages update mysql to version 4.1.12, fixing a number of problems.
  Also, support for SSL-encrypted connections to the database server is now
  provided.

  All users of mysql are advised to upgrade to these updated packages.




Solution : http://rhn.redhat.com/errata/RHSA-2005-685.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mysql packages";
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
if ( rpm_check( reference:"mysql-4.1.12-3.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-bench-4.1.12-3.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-4.1.12-3.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-server-4.1.12-3.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mysql-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1636", value:TRUE);
}

set_kb_item(name:"RHSA-2005-685", value:TRUE);
