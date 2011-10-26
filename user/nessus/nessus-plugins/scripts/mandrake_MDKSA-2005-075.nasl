#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:075
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18105);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0706");
 
 name["english"] = "MDKSA-2005:075: libcdaudio1";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:075 (libcdaudio1).



A buffer overflow bug was found by Joseph VanAndel in the way that grip handles
data returned by CDDB servers. If a user connected to a malicious CDDB server,
an attacker could execute arbitrary code on the user's machine. This same
vulnerability is present in the libcdaudio1 code.

The updated packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:075
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libcdaudio1 package";
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
if ( rpm_check( reference:"libcdaudio1-0.99.10-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcdaudio1-devel-0.99.10-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcdaudio1-0.99.10-2.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcdaudio1-devel-0.99.10-2.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libcdaudio1-", release:"MDK10.1")
 || rpm_exists(rpm:"libcdaudio1-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-0706", value:TRUE);
}
