#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:043
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19333);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "SUSE-SA:2005:043: zlib";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:043 (zlib).


The previous zlib update for CVE-2005-2096 fixed a flaw in zlib that
could allow a carefully crafted compressed stream to crash an
application. While the original patch corrected the reported
overflow, Markus Oberhumer discovered additional ways a stream could
trigger an overflow. This update fixes those problems as well.

This issue is tracked by the Mitre CVE ID CVE-2005-1849.

Since only zlib 1.2.x is affected, older SUSE products are not
affected by this problem.


Solution : http://www.suse.de/security/advisories/2005_43_zlib.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the zlib package";
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
if ( rpm_check( reference:"zlib-1.2.1-70.12", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.2.1-70.12", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-1.2.1-74.4", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.2.1-74.4", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-1.2.2-5.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.2.2-5.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
