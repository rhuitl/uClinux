#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:015
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20794);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3538", "CVE-2005-3539");
 
 name["english"] = "MDKSA-2006:015: hylafax";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:015 (hylafax).



Patrice Fournier discovered the faxrcvd/notify scripts (executed as the uucp/
fax user) run user-supplied input through eval without any attempt at
sanitising it first. This would allow any user who could submit jobs to
HylaFAX, or through telco manipulation control the representation of callid
information presented to HylaFAX to run arbitrary commands as the uucp/fax
user. (CVE-2005-3539, only 'notify' in the covered versions) Updated packages
were also reviewed for vulnerability to an issue where if PAM is disabled, a
user could log in with no password. (CVE-2005-3538) In addition, some fixes to
the packages for permissions, and the %pre/%post scripts were backported from
cooker. (#19679) The updated packages have been patched to correct these
issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:015
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the hylafax package";
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
if ( rpm_check( reference:"hylafax-4.2.0-1.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.2.0-1.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.2.0-1.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-4.2.0-1.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-devel-4.2.0-1.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.2.0-3.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.2.0-3.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.2.0-3.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-4.2.0-3.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-devel-4.2.0-3.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.2.1-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.2.1-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.2.1-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-4.2.1-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-devel-4.2.1-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"hylafax-", release:"MDK10.1")
 || rpm_exists(rpm:"hylafax-", release:"MDK10.2")
 || rpm_exists(rpm:"hylafax-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3538", value:TRUE);
 set_kb_item(name:"CVE-2005-3539", value:TRUE);
}
