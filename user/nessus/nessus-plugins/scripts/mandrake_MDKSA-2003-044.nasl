#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:044
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14028);
 script_bugtraq_id(7295);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0196", "CVE-2003-0201");
 
 name["english"] = "MDKSA-2003:044: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:044 (samba).


An exploitable buffer overflow was discovered in the Samba server that can lead
to an anonymous remote root compromise. The Samba Team also discovered some
potential overflows during an internal code audit which was done in response to
the previously noted buffer overflow problem.
All versions of Samba prior to 2.2.8a are vulnerable. The provided updates
contain a patch from the Samba Team to correct the issue.
An exploit is known to exist and all Mandrake Linux users are encouraged to
upgrade immediately.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:044
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the samba package";
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
if ( rpm_check( reference:"nss_wins-2.2.7a-9.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.7a-9.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.2.7a-9.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-doc-2.2.7a-9.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-server-2.2.7a-9.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-2.2.7a-9.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-winbind-2.2.7a-9.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nss_wins-2.2.7a-9.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.7a-9.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.2.7a-9.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-doc-2.2.7a-9.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-server-2.2.7a-9.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-2.2.7a-9.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-winbind-2.2.7a-9.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nss_wins-2.2.7a-9.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.7a-9.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.2.7a-9.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-doc-2.2.7a-9.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-server-2.2.7a-9.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-2.2.7a-9.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-winbind-2.2.7a-9.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"samba-", release:"MDK8.2")
 || rpm_exists(rpm:"samba-", release:"MDK9.0")
 || rpm_exists(rpm:"samba-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0196", value:TRUE);
 set_kb_item(name:"CVE-2003-0201", value:TRUE);
}
