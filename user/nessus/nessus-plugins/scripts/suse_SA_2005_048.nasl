#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:048
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19927);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "SUSE-SA:2005:048: pcre";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:048 (pcre).


A vulnerability was found in the PCRE regular expression handling
library which allows an attacker to crash or overflow a buffer in the
program by specifying a special regular expression.

Since this library is used in a large number of packages, including
apache2, php4, exim, postfix and similar, a remote attack could be
possible.

This is tracked by the Mitre CVE ID CVE-2005-2491.


Solution : http://www.suse.de/security/advisories/2005_48_pcre.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pcre package";
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
if ( rpm_check( reference:"pcre-4.4-112", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pcre-devel-4.4-112", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pcre-4.4-109.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pcre-devel-4.4-109.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pcre-4.5-2.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pcre-devel-4.5-2.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pcre-5.0-3.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pcre-devel-5.0-3.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
