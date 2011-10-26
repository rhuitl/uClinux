#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:030
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16359);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0077");
 
 name["english"] = "MDKSA-2005:030: perl-DBI";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:030 (perl-DBI).



Javier Fernandez-Sanguino Pena disovered the perl5 DBI library created a
temporary PID file in an insecure manner, which could be exploited by a
malicious user to overwrite arbitrary files owned by the user executing the
parts of the library.

The updated packages have been patched to prevent these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:030
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the perl-DBI package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"perl-DBI-1.40-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-DBI-ProfileDumper-Apache-1.40-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-DBI-proxy-1.40-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-DBI-1.43-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-DBI-ProfileDumper-Apache-1.43-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-DBI-proxy-1.43-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-DBI-1.38-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-DBI-ProfileDumper-Apache-1.38-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-DBI-proxy-1.38-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"perl-DBI-", release:"MDK10.0")
 || rpm_exists(rpm:"perl-DBI-", release:"MDK10.1")
 || rpm_exists(rpm:"perl-DBI-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2005-0077", value:TRUE);
}
