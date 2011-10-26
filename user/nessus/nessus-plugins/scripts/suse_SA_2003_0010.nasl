#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:0010
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13776);
 script_bugtraq_id(6510, 6512);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0031", "CVE-2003-0032");
 
 name["english"] = "SUSE-SA:2003:0010: libmcrypt";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:0010 (libmcrypt).


Libmcrypt is a data encryption library that is able to load crypto-
modules at run-time by using libltdl.
Versions of libmcrypt prior to 2.5.5 include several buffer overflows
that can be triggered by passing very long input to the mcrypt_*
functions.
The way libmcrypt handles dynamic crypto-modules via libltdl leads
to memory-leaks that can cause a Denial-of-Service condition. This
Problem can just be solved by linking modules static. This security
update does not solve the memory-leak problem to avoid compatibility
problems. Future releases of libmcrypt will be linked statically.

To add the new library to the shared library cache you have to run
ldconfig(8) as root. Additionally every program that is linked with
libmcrypt needs to be restarted. ldd(1) can be used to find out which
libraries are used by a program.
Another way to determine which process uses a shared library that
had been deleted is:
lsof -n 2>/dev/null | grep RPMDELETE | cut -d ' '  -f 1 | sort | uniq


There is no temporary fix known. Please install the new packages from
our FTP servers.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_010_libmcrypt.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libmcrypt package";
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
if ( rpm_check( reference:"libmcrypt-2.4.7-19", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libmcrypt-devel-2.4.7-19", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libmcrypt-2.4.10-59", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libmcrypt-devel-2.4.10-59", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libmcrypt-2.4.15-98", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libmcrypt-devel-2.4.15-98", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libmcrypt-2.4.20-114", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libmcrypt-devel-2.4.20-114", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libmcrypt-2.5.2-48", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libmcrypt-devel-2.5.2-48", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"libmcrypt-", release:"SUSE7.1")
 || rpm_exists(rpm:"libmcrypt-", release:"SUSE7.2")
 || rpm_exists(rpm:"libmcrypt-", release:"SUSE7.3")
 || rpm_exists(rpm:"libmcrypt-", release:"SUSE8.0")
 || rpm_exists(rpm:"libmcrypt-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2003-0031", value:TRUE);
 set_kb_item(name:"CVE-2003-0032", value:TRUE);
}
