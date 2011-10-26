#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:008
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20923);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:008: openssh";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:008 (openssh).


A problem in the handling of scp in openssh could be used to execute
commands on remote hosts even using a scp-only configuration.

This requires doing a remote-remote scp and a hostile server. (CVE-2006-0225)

On SUSE Linux Enterprise Server 9 the xauth pollution problem was fixed too.

The security fix changes the handling of quoting filenames which might
break automated scripts using this functionality.

Please check that your automated scp scripts still work after the
update.


Solution : http://www.suse.de/security/advisories/2006_08_openssh.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssh package";
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
if ( rpm_check( reference:"openssh-4.1p1-10.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-4.1p1-10.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-4.1p1-11.16", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-4.1p1-11.16", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-3.9p1-3.6", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.9p1-3.6", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-3.9p1-12.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.9p1-12.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
