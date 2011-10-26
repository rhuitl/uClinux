#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:223
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20454);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3912");
 
 name["english"] = "MDKSA-2005:223: webmin";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:223 (webmin).



Jack Louis discovered a format string vulnerability in miniserv.pl Perl web
server in Webmin before 1.250 and Usermin before 1.180, with syslog logging
enabled. This can allow remote attackers to cause a denial of service (crash or
memory consumption) and possibly execute arbitrary code via format string
specifiers in the username parameter to the login form, which is ultimately
used in a syslog call.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:223
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the webmin package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"webmin-1.150-3.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"webmin-1.180-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"webmin-1.220-9.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"webmin-", release:"MDK10.1")
 || rpm_exists(rpm:"webmin-", release:"MDK10.2")
 || rpm_exists(rpm:"webmin-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3912", value:TRUE);
}
