#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:052
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19931);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2005:052: apache2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:052 (apache2).



Solution : http://www.suse.de/security/advisories/2005_52_apache2.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the apache2 package";
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
if ( rpm_check( reference:"apache2-2.0.48-155", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libapr0-2.0.48-155", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.0.48-155", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.0.48-155", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-devel-2.0.48-155", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-leader-2.0.48-155", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-metuxmpm-2.0.48-155", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-2.0.49-27.34", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libapr0-2.0.49-27.34", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.0.49-27.34", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.0.49-27.34", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-devel-2.0.49-27.34", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-2.0.50-7.7", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libapr0-2.0.50-7.7", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.0.50-7.7", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.0.50-7.7", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-devel-2.0.50-7.7", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-2.0.53-9.5", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libapr0-2.0.53-9.5", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.0.53-9.5", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.0.53-9.5", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-devel-2.0.53-9.5", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
