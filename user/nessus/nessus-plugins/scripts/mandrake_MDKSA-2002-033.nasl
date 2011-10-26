#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:033
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13939);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:033: webmin";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:033 (webmin).


A vulnerability exists in all versions of Webmin prior to 0.970 that allows a
remote attacker to login to Webmin as any user. All users of Webmin are
encouraged to upgrade immediately.
Users of Mandrake Linux 8.0 and earlier will need to install some additional
perl modules for this new version of webmin to work correctly.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:033
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the webmin package";
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
if ( rpm_check( reference:"perl-Authen-PAM-0.12-1.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Net_SSLeay-1.05-4.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"webmin-0.970-1.3mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Authen-PAM-0.12-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"webmin-0.970-1.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Authen-PAM-0.12-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"webmin-0.970-1.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"webmin-0.970-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"webmin-0.970-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
