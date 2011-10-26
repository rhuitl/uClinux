#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:0004
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13770);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1363");
 
 name["english"] = "SUSE-SA:2003:0004: libpng";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:0004 (libpng).


The library libpng provides several functions to encode, decode and
manipulate Portable Network Graphics (PNG) image files.
Due to wrong calculation of some loop offset values a buffer overflow
can occur. The buffer overflow can lead to Denial-of-Service or even
to remote compromise.

After updating libpng all applications that use libpng should be
restarted. Due to the fact that a lot of applications are linked
with libpng it may be necessary to switch to runlevel S and back
to the previous runlevel or even to reboot the system.

There is no temporary fix known. Please install the new packages from
our FTP servers.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_004_libpng.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libpng package";
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
if ( rpm_check( reference:"libpng-2.1.0.8-17", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-2.1.0.10-57", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-2.1.0.12-160", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-2.1.0.12-160", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-1.2.4-58", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"libpng-", release:"SUSE7.1")
 || rpm_exists(rpm:"libpng-", release:"SUSE7.2")
 || rpm_exists(rpm:"libpng-", release:"SUSE7.3")
 || rpm_exists(rpm:"libpng-", release:"SUSE8.0")
 || rpm_exists(rpm:"libpng-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2002-1363", value:TRUE);
}
