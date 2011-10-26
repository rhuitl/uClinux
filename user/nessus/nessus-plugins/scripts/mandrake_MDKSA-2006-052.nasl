#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:052
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21004);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0884");
 
 name["english"] = "MDKSA-2006:052: mozilla-thunderbird";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:052 (mozilla-thunderbird).



The WYSIWYG rendering engine in Mozilla Thunderbird 1.0.7 and earlier allows
user-complicit attackers to bypass javascript security settings and obtain
sensitive information or cause a crash via an e-mail containing a javascript
URI in the SRC attribute of an IFRAME tag, which is executed when the user
edits the e-mail. Updated packages have been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:052
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
if ( rpm_check( reference:"mozilla-thunderbird-1.0.6-7.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-1.0.6-7.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmime-1.0.6-7.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mozilla-thunderbird-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-0884", value:TRUE);
}
