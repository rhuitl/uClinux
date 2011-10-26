#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:028
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13797);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2003:028: cups";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:028 (cups).


The well known Common Unix Printing System (CUPS) was found vulnerable
to a remote Denial of Service attack. The CUPS daemon will stop serving
clients if the second carriage return in a request is not sent to
complete the header.
Since the vulnerability occurs before any authorization or address
verification there is no other workaround than shutting down the
CUPS server.

To be sure the update takes effect you have to restart the CUPS daemon
by executing the following command as root:

'rccups try-restart'

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_028.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cups package";
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
if ( rpm_check( reference:"cups-1.1.6-128", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.6-128", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.10-99", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.10-99", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cups-client-1.1.10-99", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.10-99", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.12-95", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.12-95", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cups-client-1.1.12-95", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.12-95", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.15-98", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.15-98", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cups-client-1.1.15-98", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.15-98", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.18-77", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.18-77", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cups-client-1.1.18-77", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.18-77", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
