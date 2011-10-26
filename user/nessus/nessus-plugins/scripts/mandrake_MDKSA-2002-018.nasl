#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:018
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13926);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:018: cyrus-sasl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:018 (cyrus-sasl).


Kari Hurtta discovered that a format bug exists in the Cyrus SASL library, which
is used to provide an authentication API for mail clients and servers, as well
as other services such as LDAP. The format bug was found in one of the logging
functions which could be used by an attacker to obtain acces to a machine or to
possibly acquire elevated privileges. Thanks to the SuSE security team for
providing the fix.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:018
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cyrus-sasl package";
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
if ( rpm_check( reference:"cyrus-sasl-1.5.27-2.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl7-1.5.27-2.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl7-devel-1.5.27-2.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl7-plug-anonymous-1.5.27-2.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl7-plug-crammd5-1.5.27-2.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl7-plug-digestmd5-1.5.27-2.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl7-plug-login-1.5.27-2.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl7-plug-plain-1.5.27-2.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-1.5.27-2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl7-1.5.27-2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl7-devel-1.5.27-2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl7-plug-anonymous-1.5.27-2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl7-plug-crammd5-1.5.27-2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl7-plug-digestmd5-1.5.27-2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl7-plug-login-1.5.27-2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsasl7-plug-plain-1.5.27-2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
