#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:027
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21623);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:027: cron";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:027 (cron).


Vixie Cron is the default CRON daemon in all SUSE Linux based
distributions.

The code in do_command.c in Vixie cron does not check the return code
of a setuid call, which might allow local users to gain root privileges
if setuid fails in cases such as PAM failures or resource limits.

This problem is known to affect only distributions with Linux 2.6
kernels, but the package was updated for all distributions for
completeness.

This problem is tracked by the Mitre CVE ID CVE-2006-2607.


Solution : http://www.suse.de/security/advisories/2006-05-32.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cron package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"cron-4.1-26.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cron-3.0.1-920.12", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cron-4.1-14.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cron-4.1-20.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
