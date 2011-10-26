#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16354);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0227");
 
 name["english"] = "Fedora Core 2 2005-125: postgresql";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-125 (postgresql).

PostgreSQL is an advanced Object-Relational database management system
(DBMS) that supports almost all SQL constructs (including
transactions, subselects and user-defined types and functions).


* Mon Feb 07 2005 Tom Lane 7.4.7-1.FC2.2

- Put regression tests under /usr/lib64 on 64-bit archs, since .so
files
are not architecture-independent.

* Mon Feb 07 2005 Tom Lane 7.4.7-1.FC2.1

- Update to PostgreSQL 7.4.7 (fixes CVE-2005-0227 and other issues).
- Update to PyGreSQL 3.6.1.
- Add versionless symlinks to jar files (bz#145744)



Solution : http://www.fedoranews.org/blog/index.php?p=375
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the postgresql package";
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
if ( rpm_check( reference:"postgresql-7.4.7-1.FC2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-7.4.7-1.FC2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-7.4.7-1.FC2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-7.4.7-1.FC2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-7.4.7-1.FC2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-7.4.7-1.FC2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-7.4.7-1.FC2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-tcl-7.4.7-1.FC2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-python-7.4.7-1.FC2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-jdbc-7.4.7-1.FC2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-test-7.4.7-1.FC2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-debuginfo-7.4.7-1.FC2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"postgresql-", release:"FC2") )
{
 set_kb_item(name:"CVE-2005-0227", value:TRUE);
}
