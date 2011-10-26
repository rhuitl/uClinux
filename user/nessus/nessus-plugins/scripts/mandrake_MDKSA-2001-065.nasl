#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:065
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13880);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2001:065: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:065 (openssl).


The pseudo-random number generator in OpenSSL versions up to 0.9.6a has a design
flaw. By knowing the output of specific PRNG requests, an attacker would be able
to determine the PRNG's internal state and thus predict future PRNG output.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:065
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssl package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"openssl-0.9.5a-3.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.5a-3.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.5a-8.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.5a-8.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6-7.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6-7.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
