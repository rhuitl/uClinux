#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:071
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20370);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2005:071: perl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:071 (perl).


Integer overflows in the format string functionality in Perl allows
attackers to overwrite arbitrary memory and possibly execute arbitrary
code via format string specifiers with large values, which causes an
integer wrap.

This requires the attacker to be able to supply format strings to the
application, which unfortunately is true for some web applications.

This issue is tracked by the Mitre CVE ID CVE-2005-3962.


Solution : http://www.suse.de/security/advisories/2005_71_perl.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the perl package";
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
if ( rpm_check( reference:"perl-5.8.7-5.3", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-5.8.1-133", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-5.8.3-32.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-5.8.5-3.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-5.8.6-5.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
