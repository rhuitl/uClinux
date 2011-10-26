#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:042
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19251);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0025");
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "SUSE-SA:2005:042: acroread 5";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:042 (acroread 5).


This update fixes a buffer overflow in Acrobat Reader versions 5,
where an attacker could execute code by providing a handcrafted PDF
to the viewer.

The Acrobat Reader 5 versions of SUSE Linux 9.0 up to 9.2, SUSE
Linux Enterprise Server 9 and Novell Linux Desktop 9 were upgraded
to Acrobat Reader 7.

Unfortunately this version upgrade introduces new dependencies. Please
use the YaST module 'Install or Remove Software' to check if there
are new dependencies and install the required packages.

Since Adobe does no longer provide updated packages that work on SUSE
Linux Enterprise Server 8, United Linux 1, and SUSE Linux Desktop 1
we are unable to provide fixed packages for these products.

The SUSE Security Team strongly advises to deinstall the acroread
package on these platforms and use alternate PDF viewers like xpdf,
kpdf, gpdf or gv.

Since this attack could be done via E-Mail messages or web pages,
this should be considered to be remote exploitable.

This issue is tracked by the Mitre CVE ID CVE-2005-1625.


Solution : http://www.suse.de/security/advisories/2005_42_acroread.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the acroread 5 package";
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
if ( rpm_check( reference:"acroread-7.0.0-9", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"acroread-7.0.0-5.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"acroread-7.0.0-7.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"acroread-7.0.0-4.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
