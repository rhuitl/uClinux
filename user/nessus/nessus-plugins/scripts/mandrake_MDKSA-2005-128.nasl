#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:128
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19888);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2005-1937", "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2263", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270");
 
 name["english"] = "MDKSA-2005:128: mozilla";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:128 (mozilla).



A number of vulnerabilities were reported and fixed in Mozilla 1.7.9. Several
vulnerabilities have been backported and patched for this update.


The updated packages have been patched to address these issue. This update also
brings the mozilla shipped in Mandriva Linux 10.1 to version 1.7.8 to ease
maintenance. As a result, new galeon and epiphany packages are also available
for 10.1, and community contribs packages that are built against mozilla have
been rebuilt and are also available via contribs.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:128
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mozilla package";
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
if ( rpm_check( reference:"epiphany-1.2.8-4.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"epiphany-devel-1.2.8-4.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"galeon-1.3.17-3.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnspr4-1.7.8-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnspr4-devel-1.7.8-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnss3-1.7.8-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnss3-devel-1.7.8-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.8-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.8-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.8-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-enigmail-1.7.8-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-enigmime-1.7.8-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.7.8-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.8-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.8-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.7.8-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mozilla-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-1937", value:TRUE);
 set_kb_item(name:"CVE-2005-2260", value:TRUE);
 set_kb_item(name:"CVE-2005-2261", value:TRUE);
 set_kb_item(name:"CVE-2005-2263", value:TRUE);
 set_kb_item(name:"CVE-2005-2265", value:TRUE);
 set_kb_item(name:"CVE-2005-2266", value:TRUE);
 set_kb_item(name:"CVE-2005-2268", value:TRUE);
 set_kb_item(name:"CVE-2005-2269", value:TRUE);
 set_kb_item(name:"CVE-2005-2270", value:TRUE);
}
