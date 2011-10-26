#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:226
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20457);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3256");
 
 name["english"] = "MDKSA-2005:226: mozilla-thunderbird";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:226 (mozilla-thunderbird).



A bug in enigmail, the GPG support extension for Mozilla MailNews and Mozilla
Thunderbird was discovered that could lead to the encryption of an email with
the wrong public key. This could potentially disclose confidential data to
unintended recipients. The updated packages have been patched to prevent this
problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:226
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
if ( rpm_check( reference:"mozilla-thunderbird-1.0.6-7.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-1.0.6-7.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmime-1.0.6-7.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mozilla-thunderbird-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3256", value:TRUE);
}
