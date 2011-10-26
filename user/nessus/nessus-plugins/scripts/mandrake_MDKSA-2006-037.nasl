#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:037
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20877);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0296");
 
 name["english"] = "MDKSA-2006:037: mozilla-firefox";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:037 (mozilla-firefox).



Mozilla and Mozilla Firefox allow remote attackers to cause a denial of service
(CPU consumption and delayed application startup) via a web site with a large
title, which is recorded in history.dat but not processed efficiently during
startup. (CVE-2005-4134) The Javascript interpreter (jsinterp.c) in Mozilla and
Firefox before 1.5.1 does not properly dereference objects, which allows remote
attackers to cause a denial of service (crash) or execute arbitrary code via
unknown attack vectors related to garbage collection. (CVE-2006-0292) The
XULDocument.persist function in Mozilla, Firefox before 1.5.0.1, and SeaMonkey
before 1.0 does not validate the attribute name, which allows remote attackers
to execute arbitrary Javascript by injecting RDF data into the user's
localstore.rdf file. (CVE-2006-0296) Updated packages are patched to address
these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:037
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
if ( rpm_check( reference:"libnspr4-1.0.6-16.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnspr4-devel-1.0.6-16.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnss3-1.0.6-16.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnss3-devel-1.0.6-16.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-firefox-1.0.6-16.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-firefox-devel-1.0.6-16.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mozilla-firefox-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-4134", value:TRUE);
 set_kb_item(name:"CVE-2006-0292", value:TRUE);
 set_kb_item(name:"CVE-2006-0296", value:TRUE);
}
