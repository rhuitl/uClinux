#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:092
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14723);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0807", "CVE-2004-0808");
 
 name["english"] = "MDKSA-2004:092: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:092 (samba).


Two vulnerabilities were discovered in samba 3.0.x; the first is a defect in
smbd's ASN.1 parsing that allows an attacker to send a specially crafted packet
during the authentication request which will send the newly spawned smbd process
into an infinite loop. As a result, it is possible to use up all available
memory on the server.
The second vulnerability is in nmbd's processing of mailslot packets which could
allow an attacker to anonymously crash nmbd.
The provided packages are patched to protect against these two vulnerabilities.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:092
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
if ( rpm_check( reference:"libsmbclient0-3.0.6-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsmbclient0-devel-3.0.6-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nss_wins-3.0.6-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.6-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-3.0.6-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-doc-3.0.6-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-passdb-mysql-3.0.6-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-passdb-pgsql-3.0.6-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-passdb-xml-3.0.6-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-server-3.0.6-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-3.0.6-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-winbind-3.0.6-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"samba-", release:"MDK10.0") )
{
 set_kb_item(name:"CVE-2004-0807", value:TRUE);
 set_kb_item(name:"CVE-2004-0808", value:TRUE);
}
