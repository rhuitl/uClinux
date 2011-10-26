#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15930);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0381", "CVE-2004-0457", "CVE-2004-0837", "CVE-2004-0957");
 
 name["english"] = "Fedora Core 2 2004-530: mysql";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-530 (mysql).

MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries. This package
contains the MySQL client programs, the client shared libraries, and
generic MySQL files.


* Tue Oct 12 2004 Tom Lane 3.23.58-9.1

- fix security issues CVE-2004-0835, CVE-2004-0836, CVE-2004-0837
(bugs #135372, 135375, 135387)
- fix privilege escalation on GRANT ALL ON `Foo_Bar` (CVE-2004-0957)
- fix multilib problem with mysqlbug and mysql_config
- adjust chkconfig priority per bug #128852
- remove bogus quoting per bug #129409 (MySQL 4.0 has done likewise)
- add sleep to mysql.init restart(); may or may not fix bug #133993
- fix low-priority security issues CVE-2004-0388, CVE-2004-0381,
CVE-2004-0457
(bugs #119442, 125991, 130347, 130348)
- fix bug with dropping databases under recent kernels (bug #124352)



Solution : http://www.fedoranews.org/blog/index.php?p=178
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mysql package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"mysql-3.23.58-9.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-server-3.23.58-9.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-3.23.58-9.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-bench-3.23.58-9.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-debuginfo-3.23.58-9.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"mysql-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0381", value:TRUE);
 set_kb_item(name:"CVE-2004-0457", value:TRUE);
 set_kb_item(name:"CVE-2004-0837", value:TRUE);
 set_kb_item(name:"CVE-2004-0957", value:TRUE);
}
