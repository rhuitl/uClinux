#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:053
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14037);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1391", "CVE-2002-1392");
 
 name["english"] = "MDKSA-2003:053: mgetty";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:053 (mgetty).


Two vulnerabilities were discovered in mgetty versions prior to 1.1.29. An
internal buffer could be overflowed if the caller name reported by the modem,
via Caller ID information, was too long. As well, the faxspool script that comes
with mgetty used a simple permissions scheme to allow or deny fax transmission
privileges. Because the spooling directory used for outgoing faxes was
world-writeable, this scheme was easily circumvented.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:053
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mgetty package";
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
if ( rpm_check( reference:"mgetty-1.1.30-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mgetty-contrib-1.1.30-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mgetty-sendfax-1.1.30-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mgetty-viewfax-1.1.30-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mgetty-voice-1.1.30-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mgetty-1.1.30-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mgetty-contrib-1.1.30-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mgetty-sendfax-1.1.30-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mgetty-viewfax-1.1.30-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mgetty-voice-1.1.30-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mgetty-", release:"MDK8.2")
 || rpm_exists(rpm:"mgetty-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1391", value:TRUE);
 set_kb_item(name:"CVE-2002-1392", value:TRUE);
}
