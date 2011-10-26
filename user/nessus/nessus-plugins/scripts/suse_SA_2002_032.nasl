#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2002:032
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13754);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "SUSE-SA:2002:032: xf86";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2002:032 (xf86).


The xf86 package contains various libraries and programs which are
fundamental for the X server to function.
The libX11.so library from this package dynamically loads other libraries
where the pathname is controlled by the user invoking the program linked
against libX11.so. Unfortunately, libX11.so also behaves the same way when
linked against setuid programs. This behavior allows local users to
execute arbitrary code under a different UID which can be the root-UID in
the worst case.
libX11.so has been fixed to check for calls from setuid programs. It
denies loading of user controlled libraries in this case.
We recommend an update in any case since there is no easy workaround
possible except removing the setuid bit from any program linked against
libX11.so.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2002_032_xf86.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xf86 package";
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
if ( rpm_check( reference:"xshared-4.2.0-174", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"xdevel-4.2.0-174", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
