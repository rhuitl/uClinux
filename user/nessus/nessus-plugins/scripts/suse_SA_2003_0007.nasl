#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:0007
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13772);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0015");
 
 name["english"] = "SUSE-SA:2003:0007: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:0007 (cvs).


CVS (Concurrent Versions System) is a version control system which
helps to manage concurrent editing of files by various authors.
Stefan Esser of e-matters reported a 'double free' bug in CVS
server code for handling directory requests. This free() call allows
an attacker with CVS read access to compromise a CVS server.
Additionally two features ('Update-prog' and 'Checkin-prog') were
disabled to stop clients with write access to execute arbitrary code
on the server. These features may be configurable at run-time in future
releases of CVS server.

There is no temporary fix known other then disable public access to the
CVS server. You do not need to update the cvs package as long as you
need 'Update-prog' and 'Checkin-prog' feature and work in a trusted
environment.
Otherwise install the new packages from our FTP servers please.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_007_cvs.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cvs package";
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
if ( rpm_check( reference:"cvs-1.11-230", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11-231", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11-230", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.1p1-235", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.1p1-235", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"cvs-", release:"SUSE7.1")
 || rpm_exists(rpm:"cvs-", release:"SUSE7.2")
 || rpm_exists(rpm:"cvs-", release:"SUSE7.3")
 || rpm_exists(rpm:"cvs-", release:"SUSE8.0")
 || rpm_exists(rpm:"cvs-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2003-0015", value:TRUE);
}
