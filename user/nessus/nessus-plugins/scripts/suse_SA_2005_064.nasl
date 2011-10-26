#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:064
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20209);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2005:064: pwdutils, shadow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:064 (pwdutils, shadow).


Thomas Gerisch found that the setuid 'chfn' program contained in the
pwdutils suite insufficiently checks it's arguments when changing
the GECOS field. This bug leads to a trivially exploitable local
privilege escalation that allows users to gain root access.

We like to thank Thomas Gerisch for pointing out the problem.


Solution : http://www.suse.de/security/advisories/2005_64_pwdutils.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pwdutils, shadow package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"pwdutils-3.0.4-4.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"shadow-4.0.3-267", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pwdutils-2.6.4-2.18.3", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pwdutils-2.6.90-6.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pwdutils-2.6.96-4.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
