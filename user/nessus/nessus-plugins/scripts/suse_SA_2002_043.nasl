#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2002:043
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13764);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2002:043: traceroute-nanog/nkitb";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2002:043 (traceroute-nanog/nkitb).


Traceroute is a tool that can be used to track packets in a TCP/IP
network to determine it's route or to find out about not working
routers.
Traceroute-nanog requires root privilege to open a raw socket. It
does not relinquish these privileges after doing so. This allows
a malicious user to gain root access by exploiting a buffer
overflow at a later point.

For all products prior to 8.1, the traceroute package
contains the NANOG implementation. This package is installed by
default. Starting with 8.1, SUSE LINUX contains a traceroute program
rewritten by Olaf Kirch that does not require root privileges anymore.
This version of traceroute is not vulnerable.

This is the first update for the traceroute package on the SUSE LINUX
distributions 7.1 through 8.0. We have changed the version string in
the update packages to read '6.x' instead of the former 'nanog_6.x' to
enable a clean comparison between version numbers. This change is
misleading in that it suggests that the package name has been changed.
Since only the version string is affected, the name of the package
remains the same.

As a workaround you can remove the setuid bit or just allow trusted
users to execute traceroute-nanog.
Become root and add the following line to /etc/permissions.local:
'/usr/sbin/traceroute          root.trusted    4750'
This line will keep the setuid root bit for /usr/sbin/traceroute
and just allow users in group trusted to execute the binary.
To make the permission change and keep it permanent you have to
run chkstat(8):
'chkstat -set /etc/permissions.local'

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2002_043_traceroute_nanog_nkitb.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the traceroute-nanog/nkitb package";
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
if ( rpm_check( reference:"nkitb-2002.11.6-0", release:"SUSE7.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"traceroute-6.0-0", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"traceroute-6.1.1-0", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"traceroute-6.1.1-0", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"traceroute-6.1.1-0", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
