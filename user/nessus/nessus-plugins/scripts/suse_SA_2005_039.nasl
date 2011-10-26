#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:039
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19248);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "SUSE-SA:2005:039: zlib";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:039 (zlib).


A denial of service condition was fixed in the zlib library.

Any program using zlib to decompress data can be crashed by a specially
handcrafted invalid data stream. This includes web browsers or email
programs able to view PNG images (which are compressed by zlib),
allowing remote attackers to crash browser sessions or potentially
anti virus programs using this vulnerability.

This issue is tracked by the Mitre CVE ID CVE-2005-2096.

Since only zlib 1.2.x is affected, older SUSE products are not affected
by this problem.


Solution : http://www.suse.de/security/advisories/2005_39_zlib.html
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
if ( rpm_check( reference:"zlib-1.2.1-70.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.2.1-70.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-1.2.1-74.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.2.1-74.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-1.2.2-5.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.2.2-5.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
