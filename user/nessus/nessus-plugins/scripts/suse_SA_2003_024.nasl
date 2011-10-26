#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:024
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13794);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2003:024: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:024 (openssl).


Researchers from the University of Stanford have discovered certain
weaknesses in OpenSSL's RSA decryption algorithm. It allows remote
attackers to compute the private RSA key of a server by observing
its timing behavior. This bug has been fixed by enabling 'RSA blinding',
by default.
Additionally an extension of the 'Bleichenbacher attack' has been
developed by Czech researchers against OpenSSL. This weakness has
also been fixed.


Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_024_openssl.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssl package";
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
if ( rpm_check( reference:"openssl-0.9.6a-81", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6a-81", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6a-82", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6a-82", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6b-156", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6b-156", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6c-85", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6c-85", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6g-68", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6g-68", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6i-12", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6i-12", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
