#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:110
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15546);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0784", "CVE-2004-0785");
 
 name["english"] = "MDKSA-2004:110: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:110 (gaim).


More vulnerabilities have been discovered in the gaim instant messenger client.
The vulnerabilities pertinent to version 0.75, which is the version shipped with
Mandrakelinux 10.0, are: installing smiley themes could allow remote attackers
to execute arbitrary commands via shell metacharacters in the filename of the
tar file that is dragged to the smiley selector. There is also a buffer overflow
in the way gaim handles receiving very long URLs.
The provided packages have been patched to fix these problems. These issues,
amongst others, have been fixed upstream in version 0.82.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:110
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gaim package";
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
if ( rpm_check( reference:"gaim-0.75-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-encrypt-0.75-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-festival-0.75-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-perl-0.75-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-0.75-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gaim-", release:"MDK10.0") )
{
 set_kb_item(name:"CVE-2004-0784", value:TRUE);
 set_kb_item(name:"CVE-2004-0785", value:TRUE);
}
