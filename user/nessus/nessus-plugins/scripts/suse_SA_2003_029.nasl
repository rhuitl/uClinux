#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:029
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13798);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2003:029: pptpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:029 (pptpd).


The PPTP daemon contains a remotely exploitable buffer overflow which
was introduced due to a integer overflow in the third argument passed
to the read() library call. This bug has been fixed.
Since there is no workaround other than shutting down the PPTP daemon
an update is strongly recommended if you need a PPTP server running.

To be sure the update takes effect you have to restart the PPTP daemon
by executing the following command as root:

'rcpptpd restart'

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_029.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pptpd package";
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
if ( rpm_check( reference:"pptpd-1.1.2-411", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"pptpd-1.1.2-412", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"pptpd-1.1.2-412", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"pptpd-1.1.2-413", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"pptpd-1.1.2-418", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
