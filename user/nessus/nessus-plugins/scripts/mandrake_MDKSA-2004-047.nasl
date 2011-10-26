#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:047
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14146);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0411");
 
 name["english"] = "MDKSA-2004:047: kdelibs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:047 (kdelibs).


A vulnerability in the Opera web browser was identified by iDEFENSE; the same
type of vulnerability exists in KDE. The telnet, rlogin, ssh, and mailto URI
handlers do not check for '-' at the beginning of the hostname passed, which
makes it possible to pass an option to the programs started by the handlers.
This can allow remote attackers to create or truncate arbitrary files.
The updated packages contain patches provided by the KDE team to fix this
problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:047
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs package";
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
if ( rpm_check( reference:"kdelibs-common-3.2-36.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-3.2-36.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-devel-3.2-36.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-common-3.1.3-35.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-3.1.3-35.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-devel-3.1.3-35.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kdelibs-", release:"MDK10.0")
 || rpm_exists(rpm:"kdelibs-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0411", value:TRUE);
}
