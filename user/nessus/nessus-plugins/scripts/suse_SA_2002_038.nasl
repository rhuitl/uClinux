#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2002:038
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13759);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-0972");
 
 name["english"] = "SUSE-SA:2002:038: postgresql";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2002:038 (postgresql).


The PostgreSQL Object-Relational DBMS was found vulnerable to several
security related buffer overflow problems.
The buffer overflows are located in:
* handling long datetime input
* lpad() and rpad() function with multibyte
* repeat() function
* TZ and SET TIME ZONE environment variables
These bugs could just be exploited by attackers who have access to the
postgresql server to gain the privileges postgres user ID .

The PostgreSQL package is not installed by default.
A temporary fix is not known.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2002_038_postgresql.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the postgresql package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"postgresql-libs-7.1.3-116", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-7.1.3-116", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-7.1.3-116", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-7.1.3-116", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-7.1.3-116", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-jdbc-7.1.3-116", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-odbc-7.1.3-116", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-perl-7.1.3-116", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-python-7.1.3-116", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-7.1.3-116", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-tcl-7.1.3-116", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-test-7.1.3-116", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-tk-7.1.3-116", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-7.2-103", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-7.2-103", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-7.2-103", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-7.2-103", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-7.2-103", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-jdbc-7.2-103", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-odbc-7.2-103", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-perl-7.2-103", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-python-7.2-103", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-7.2-103", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-tcl-7.2-103", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-test-7.2-103", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-tk-7.2-103", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"postgresql-", release:"SUSE7.3")
 || rpm_exists(rpm:"postgresql-", release:"SUSE8.0") )
{
 set_kb_item(name:"CVE-2002-0972", value:TRUE);
}
