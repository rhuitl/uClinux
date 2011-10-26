#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19259);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Fedora Core 4 2005-557: mysql";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-557 (mysql).

MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries. This package
contains the MySQL client programs, the client shared library, and
generic MySQL files.

Update Information:

Update to MySQL 4.1.12 (includes a low-impact security fix, see bz#158689).
Repair some issues in openssl support.
Re-enable the old ISAM table type.


Solution : http://fedoranews.org//mediawiki/index.php/Fedora_Core_4_Update:_mysql-4.1.12-2.FC4.1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mysql package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"mysql-4.1.12-2.FC4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-server-4.1.12-2.FC4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-4.1.12-2.FC4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-bench-4.1.12-2.FC4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
