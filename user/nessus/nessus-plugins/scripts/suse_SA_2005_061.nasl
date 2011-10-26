#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:061
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20064);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "SUSE-SA:2005:061: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:061 (openssl).


The openssl cryptographic libraries have been updated to fix
a protocol downgrading attack which allows a man-in-the-middle
attacker to force the usage of SSLv2. This happens due to the
work-around code of SSL_OP_MSIE_SSLV2_RSA_PADDING which is included
in SSL_OP_ALL (which is commonly used in applications). (CVE-2005-2969)

Additionally this update adds the Geotrusts Equifax Root1 CA certificate
to allow correct certification against Novell Inc. websites and
services. The same CA is already included in Mozilla, KDE, and curl,
which use separate certificate stores.


Solution : http://www.suse.de/security/advisories/2005_61_openssl.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssl package";
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
if ( rpm_check( reference:"openssl-0.9.7g-2.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7g-2.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7b-135", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7b-135", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7d-15.15.3", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7d-15.15.3", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7d-25.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7d-25.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7e-3.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7e-3.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
