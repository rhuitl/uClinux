#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2002:034
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13755);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2002:034: heimdal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2002:034 (heimdal).


The Heimdal package is a free Kerberos implementation offering flexible
authentication mechanisms based on the Kerberos 5 and Kerberos 4 scheme.
The SUSE Security Team has reviewed critical parts of the Heimdal
package such as the kadmind and kdc server. While doing so several
possible buffer overflows and other bugs have been uncovered and fixed.
Remote attackers can probably gain remote root access on unpatched systems.
Since these services run usually on authentication servers we consider
these bugs to be very serious. An update is strongly recommended if you are
using the Heimdal package.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2002_034_heimdal.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the heimdal package";
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
if ( rpm_check( reference:"heimdal-lib-0.3e-83", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"heimdal-0.3e-83", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"heimdal-devel-0.3e-83", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"heimdal-0.4d-132", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"heimdal-devel-0.4d-132", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"heimdal-devel-0.4e-191", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"heimdal-lib-0.4e-191", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"heimdal-0.4e-191", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
