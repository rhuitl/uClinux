#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:009
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13994);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0015");
 
 name["english"] = "MDKSA-2003:009: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:009 (cvs).


Two vulnerabilities were discoverd by Stefen Esser in the cvs program. The first
is an exploitable double free() bug within the server, which can be used to
execute arbitray code on the CVS server. To accomplish this, the attacker must
have an anonymous read-only login to the CVS server. The second vulnerability is
with the Checkin-prog and Update-prog commands. If a client has write
permission, he can use these commands to execute programs outside of the scope
of CVS, the output of which will be sent as output to the client.
This update fixes the double free() vulnerability and removes the Checkin-prog
and Update-prog commands from CVS.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:009
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cvs package";
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
if ( rpm_check( reference:"cvs-1.11.4-2.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.4-2.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.4-2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.4-2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.4-2.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cvs-", release:"MDK7.2")
 || rpm_exists(rpm:"cvs-", release:"MDK8.0")
 || rpm_exists(rpm:"cvs-", release:"MDK8.1")
 || rpm_exists(rpm:"cvs-", release:"MDK8.2")
 || rpm_exists(rpm:"cvs-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0015", value:TRUE);
}
