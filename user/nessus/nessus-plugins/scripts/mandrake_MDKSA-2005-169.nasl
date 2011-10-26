#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:169
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20425);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-2871", "CVE-2005-2968");
 
 name["english"] = "MDKSA-2005:169: mozilla-firefox";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:169 (mozilla-firefox).



A number of vulnerabilities have been discovered in Mozilla Firefox that have
been corrected in version 1.0.7:

A bug in the way Firefox processes XBM images could be used to execute
arbitrary code via a specially crafted XBM image file (CVE-2005-2701).

A bug in the way Firefox handles certain Unicode sequences could be used to
execute arbitrary code via viewing a specially crafted Unicode sequence
(CVE-2005-2702).

A bug in the way Firefox makes XMLHttp requests could be abused by a malicious
web page to exploit other proxy or server flaws from the victim's machine;
however, the default behaviour of the browser is to disallow this
(CVE-2005-2703).

A bug in the way Firefox implemented its XBL interface could be abused by a
malicious web page to create an XBL binding in such a way as to allow arbitrary
JavaScript execution with chrome permissions (CVE-2005-2704).

An integer overflow in Firefox's JavaScript engine could be manipulated in
certain conditions to allow a malicious web page to execute arbitrary code
(CVE-2005-2705).

A bug in the way Firefox displays about: pages could be used to execute
JavaScript with chrome privileges (CVE-2005-2706).

A bug in the way Firefox opens new windows could be used by a malicious web
page to construct a new window without any user interface elements (such as
address bar and status bar) that could be used to potentially mislead the user
(CVE-2005-2707).

A bug in the way Firefox proceesed URLs on the command line could be used to
execute arbitary commands as the user running Firefox; this could be abused by
clicking on a supplied link, such as from an instant messaging client
(CVE-2005-2968).

Tom Ferris reported that Firefox would crash when processing a domain name
consisting solely of soft-hyphen characters due to a heap overflow when IDN
processing results in an empty string after removing non- wrapping chracters,
such as soft-hyphens. This could be exploited to run or or install malware on
the user's computer (CVE-2005-2871).

The updated packages have been patched to address these issues and all users
are urged to upgrade immediately.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:169
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
if ( rpm_check( reference:"libnspr4-1.0.2-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnspr4-devel-1.0.2-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnss3-1.0.2-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnss3-devel-1.0.2-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-firefox-1.0.2-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-firefox-devel-1.0.2-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mozilla-firefox-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2701", value:TRUE);
 set_kb_item(name:"CVE-2005-2702", value:TRUE);
 set_kb_item(name:"CVE-2005-2703", value:TRUE);
 set_kb_item(name:"CVE-2005-2704", value:TRUE);
 set_kb_item(name:"CVE-2005-2705", value:TRUE);
 set_kb_item(name:"CVE-2005-2706", value:TRUE);
 set_kb_item(name:"CVE-2005-2707", value:TRUE);
 set_kb_item(name:"CVE-2005-2871", value:TRUE);
 set_kb_item(name:"CVE-2005-2968", value:TRUE);
}
