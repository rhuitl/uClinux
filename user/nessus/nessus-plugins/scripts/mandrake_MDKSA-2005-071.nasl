#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:071
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18052);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0965", "CVE-2005-0966", "CVE-2005-0967");
 
 name["english"] = "MDKSA-2005:071: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:071 (gaim).



More vulnerabilities have been discovered in the gaim instant messaging client:

A buffer overflow vulnerability was found in the way that gaim escapes HTML,
allowing a remote attacker to send a specially crafted message to a gaim client
and causing it to crash (CVE-2005-0965).

A bug was discovered in several of gaim's IRC processing functions that fail to
properly remove various markup tags within an IRC message. This could allow a
remote attacker to send specially crafted message to a gaim client connected to
an IRC server, causing it to crash (CVE-2005-0966).

Finally, a problem was found in gaim's Jabber message parser that would allow a
remote Jabber user to send a specially crafted message to a gaim client,
bausing it to crash (CVE-2005-0967).

Gaim version 1.2.1 is not vulnerable to these issues and is provided with this
update.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:071
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gaim package";
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
if ( rpm_check( reference:"gaim-1.2.1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-devel-1.2.1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-gevolution-1.2.1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-perl-1.2.1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-tcl-1.2.1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-1.2.1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-devel-1.2.1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gaim-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0965", value:TRUE);
 set_kb_item(name:"CVE-2005-0966", value:TRUE);
 set_kb_item(name:"CVE-2005-0967", value:TRUE);
}
