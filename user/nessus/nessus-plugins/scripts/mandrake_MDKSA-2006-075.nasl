#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:075
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21282);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0748", "CVE-2006-0749", "CVE-2006-1728", "CVE-2006-1729", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1736", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1740", "CVE-2006-1742", "CVE-2006-1790");
 
 name["english"] = "MDKSA-2006:075: mozilla-firefox";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:075 (mozilla-firefox).



A number of vulnerabilities have been discovered in the Mozilla Firefox browser
that could allow a remote attacker to craft malicious web pages that could take
advantage of these issues to execute arbitrary code with elevated privileges,
spoof content, and steal local files, cookies, or other information from web
pages. As well, some of these vulnerabilities can be exploited to execute
arbitrary code with the privileges of the user running the browser. As well,
two crasher bugs have been fixed as well. The updated packages have been
patched to fix these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:075
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mozilla-firefox package";
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
if ( rpm_check( reference:"libnspr4-1.0.6-16.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnspr4-devel-1.0.6-16.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnss3-1.0.6-16.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnss3-devel-1.0.6-16.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-firefox-1.0.6-16.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-firefox-devel-1.0.6-16.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mozilla-firefox-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-0748", value:TRUE);
 set_kb_item(name:"CVE-2006-0749", value:TRUE);
 set_kb_item(name:"CVE-2006-1728", value:TRUE);
 set_kb_item(name:"CVE-2006-1729", value:TRUE);
 set_kb_item(name:"CVE-2006-1730", value:TRUE);
 set_kb_item(name:"CVE-2006-1731", value:TRUE);
 set_kb_item(name:"CVE-2006-1732", value:TRUE);
 set_kb_item(name:"CVE-2006-1733", value:TRUE);
 set_kb_item(name:"CVE-2006-1734", value:TRUE);
 set_kb_item(name:"CVE-2006-1735", value:TRUE);
 set_kb_item(name:"CVE-2006-1736", value:TRUE);
 set_kb_item(name:"CVE-2006-1737", value:TRUE);
 set_kb_item(name:"CVE-2006-1738", value:TRUE);
 set_kb_item(name:"CVE-2006-1739", value:TRUE);
 set_kb_item(name:"CVE-2006-1740", value:TRUE);
 set_kb_item(name:"CVE-2006-1742", value:TRUE);
 set_kb_item(name:"CVE-2006-1790", value:TRUE);
}
