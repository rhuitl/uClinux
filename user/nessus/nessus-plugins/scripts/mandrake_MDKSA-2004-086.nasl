#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:086
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14335);
 script_bugtraq_id(10991, 11186, 11552);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2004-0689", "CVE-2004-0690", "CVE-2004-0721", "CVE-2004-0746");
 
 name["english"] = "MDKSA-2004:086: kdelibs/kdebase";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:086 (kdelibs/kdebase).


A number of vulnerabilities were discovered in KDE that are corrected with these
update packages.
The integrity of symlinks used by KDE are not ensured and as a result can be
abused by local attackers to create or truncate arbitrary files or to prevent
KDE applications from functioning correctly (CVE-2004-0689).
The DCOPServer creates temporary files in an insecure manner. These temporary
files are used for authentication-related purposes, so this could potentially
allow a local attacker to compromise the account of any user running a KDE
application (CVE-2004-0690). Note that only KDE 3.2.x is affected by this
vulnerability.
The Konqueror web browser allows websites to load web pages into a frame of any
other frame-based web page that the user may have open. This could potentially
allow a malicious website to make Konqueror insert its own frames into the page
of an otherwise trusted website (CVE-2004-0721).
The Konqueror web browser also allows websites to set cookies for certain
country-specific top-level domains. This can be done to make Konqueror send the
cookies to all other web sites operating under the same domain, which can be
abused to become part of a session fixation attack. All country-specific
secondary top-level domains that use more than 2 characters in the secondary
part of the domain name, and that use a secondary part other than com, net, mil,
org, gove, edu, or int are affected (CVE-2004-0746).


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:086
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs/kdebase package";
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
if ( rpm_check( reference:"kdebase-3.2-79.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-common-3.2-79.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-kate-3.2-79.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-kdeprintfax-3.2-79.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-kdm-3.2-79.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-kmenuedit-3.2-79.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-konsole-3.2-79.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-nsplugins-3.2-79.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-progs-3.2-79.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-common-3.2-36.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdebase4-3.2-79.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdebase4-devel-3.2-79.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdebase4-kate-3.2-79.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdebase4-konsole-3.2-79.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-3.2-36.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-devel-3.2-36.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-3.1.3-79.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-common-3.1.3-79.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-kate-3.1.3-79.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-kdeprintfax-3.1.3-79.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-kdm-3.1.3-79.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-konsole-3.1.3-79.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-nsplugins-3.1.3-79.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-progs-3.1.3-79.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-common-3.1.3-35.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdebase4-3.1.3-79.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdebase4-devel-3.1.3-79.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdebase4-kate-3.1.3-79.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdebase4-konsole-3.1.3-79.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-3.1.3-35.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-devel-3.1.3-35.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kdelibs-", release:"MDK10.0")
 || rpm_exists(rpm:"kdelibs-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0689", value:TRUE);
 set_kb_item(name:"CVE-2004-0690", value:TRUE);
 set_kb_item(name:"CVE-2004-0721", value:TRUE);
 set_kb_item(name:"CVE-2004-0746", value:TRUE);
}
