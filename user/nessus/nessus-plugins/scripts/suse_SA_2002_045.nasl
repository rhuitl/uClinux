#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2002:045
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13766);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2002:045: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2002:045 (samba).


Samba developer Steve Langasek found a security problem in samba, the
widely known free implementation of the SMB protocol.

The error consists of a buffer overflow in a commonly used routine
that accepts user input and may write up to 127 bytes past the end of
the buffer allocated with static length, leaving enough room for
an exploit. The resulting vulnerability can be exploited locally
in applications using the pam_smbpass Pluggable Authentication Module
(PAM). It may be possible to exploit this vulnerability remotely,
causing the running smbd to crash or even to execute arbitrary code.

The samba package is installed by default only on the SUSE LINUX
Enterprise Server. SUSE LINUX products do not have the samba and
samba-client packages installed by default.
The samba packages in SUSE LINUX version 7.1 and before are not affected
by this vulnerability.
For the bug to be exploited, your system has to be running the smbd
samba server, or an administrator must have (manually) changed the
configuration of the PAM authentification subsystem to enable the use
of the pam_smbpass module. The samba server process(es) are not activated
automatically after installation (of the package).

The samba subsystem on SUSE products is split into two different
subpackages: samba and smbclnt up to and including SUSE LINUX 7.2, on
SUSE LINUX 7.3 and newer the package names are samba and samba-client.
To completely remove the vulnerability, you should update all of the
installed packages.

We wish to express our gratitude to the samba development team and
in particular to Steve Langasek and Volker Lendecke who provided the
patches and communicated them to the vendors. Please know that the
samba team will release the new version 2.2.7 of the samba software to
address the security fix at the same time as this announcement gets
published. More information about samba (and the security fix) is
available at http://www.samba.org.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2002_045_samba.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the samba package";
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
if ( rpm_check( reference:"samba-2.2.0a-45", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"smbclnt-2.2.0a-45", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.2.1a-206", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.1a-206", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.2.3a-165", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.3a-165", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.2.5-124", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.5-124", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
