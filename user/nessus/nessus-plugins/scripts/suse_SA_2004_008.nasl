#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2004:008
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13826);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SuSE-SA:2004:008: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SuSE-SA:2004:008 (cvs).


The Concurrent Versions System (CVS) offers tools which allow developers
to share and maintain large software projects.
During the analyzation of the CVS protocol and their implementation, the
SuSE Security Team discovered a flaw within the handling of pathnames.
Evil CVS servers could specify absolute pathnames during checkouts and
updates, which allows to create arbitrary files with the permissions of
the user invoking the CVS client. This could lead to a compromise of the
system.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2004_08_cvs.html
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
if ( rpm_check( reference:"cvs-1.11.1p1-326", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.1p1-326", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.5-103", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.6-79", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
