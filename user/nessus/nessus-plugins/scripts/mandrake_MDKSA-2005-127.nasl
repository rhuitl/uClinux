#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:127-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20421);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2269", "CVE-2005-2270");
 
 name["english"] = "MDKSA-2005:127-1: mozilla-thunderbird";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:127-1 (mozilla-thunderbird).


A number of vulnerabilities were reported and fixed in Thunderbird 1.0.5 and
Mozilla 1.7.9. The following vulnerabilities have been backported and patched
for this update.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:127-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mozilla-thunderbird package";
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
if ( rpm_check( reference:"mozilla-thunderbird-1.0.2-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-devel-1.0.2-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-1.0.2-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmime-1.0.2-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mozilla-thunderbird-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2260", value:TRUE);
 set_kb_item(name:"CVE-2005-2261", value:TRUE);
 set_kb_item(name:"CVE-2005-2265", value:TRUE);
 set_kb_item(name:"CVE-2005-2266", value:TRUE);
 set_kb_item(name:"CVE-2005-2269", value:TRUE);
 set_kb_item(name:"CVE-2005-2270", value:TRUE);
}
