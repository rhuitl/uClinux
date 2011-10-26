#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19646);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0711");
 
 name["english"] = "Fedora Core 3 2005-304: mysql";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-304 (mysql).

MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries.


* Sat Apr  2 2005 Tom Lane <tgl redhat com> 3.23.58-16.FC3.1

- Repair uninitialized variable in security2 patch.
- Enable testing on 64-bit arches; continue to exclude s390x which still
has issues.

* Sat Mar 19 2005 Tom Lane <tgl redhat com> 3.23.58-15.FC3.1

- Backpatch repair for CVE-2005-0709, CVE-2005-0710, CVE-2005-0711 (bz#151051).
- Run 'make test' only on the archs we support for FC-3.




Solution : Get the newest Fedora Updates
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
if ( rpm_check( reference:"mysql-3.23.58-16.FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-server-3.23.58-16.FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-3.23.58-16.FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-bench-3.23.58-16.FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"mysql-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0711", value:TRUE);
}
