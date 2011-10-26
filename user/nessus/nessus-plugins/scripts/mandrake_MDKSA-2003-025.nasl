#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:025
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14009);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0101");
 
 name["english"] = "MDKSA-2003:025: webmin";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:025 (webmin).


A vulnerability was discovered in webmin by Cintia M. Imanishi, in the
miniserv.pl program, which is the core server of webmin. This vulnerability
allows an attacker to spoof a session ID by including special metacharacters in
the BASE64 encoding string used during the authentication process. This could
allow an attacker to gain full administrative access to webmin.
MandrakeSoft encourages all users to upgrade immediately.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:025
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
if ( rpm_check( reference:"webmin-0.970-2.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"webmin-0.970-2.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"webmin-0.970-2.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"webmin-0.970-2.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"webmin-0.990-6.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"webmin-", release:"MDK7.2")
 || rpm_exists(rpm:"webmin-", release:"MDK8.0")
 || rpm_exists(rpm:"webmin-", release:"MDK8.1")
 || rpm_exists(rpm:"webmin-", release:"MDK8.2")
 || rpm_exists(rpm:"webmin-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0101", value:TRUE);
}
