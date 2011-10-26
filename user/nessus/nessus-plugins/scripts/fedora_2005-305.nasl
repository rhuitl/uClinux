#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18333);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0711");
 
 name["english"] = "Fedora Core 2 2005-305: mysql";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-305 (mysql).

MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries.


* Sat Apr 2 2005 Tom Lane 3.23.58-16.FC2.1

- Repair uninitialized variable in security2 patch.
- Enable testing on 64-bit arches; continue to exclude s390x which
still
has issues.

* Fri Mar 18 2005 Tom Lane 3.23.58-15.FC2.1

- Backpatch repair for CVE-2005-0709, CVE-2005-0710, CVE-2005-0711
(bz#151051).
- Fix init script to not need a valid username for startup check
(bz#142328)
- Don't assume /etc/my.cnf will specify pid-file (bz#143724)



Solution : http://www.fedoranews.org/blog/index.php?p=572
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
if ( rpm_check( reference:"mysql-3.23.58-16.FC2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-server-3.23.58-16.FC2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-3.23.58-16.FC2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-bench-3.23.58-16.FC2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-debuginfo-3.23.58-16.FC2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"mysql-", release:"FC2") )
{
 set_kb_item(name:"CVE-2005-0711", value:TRUE);
}
