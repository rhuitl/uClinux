#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:028
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16294);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1079", "CVE-2005-0013", "CVE-2005-0014");
 
 name["english"] = "MDKSA-2005:028: ncpfs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:028 (ncpfs).



Erik Sjolund discovered two vulnerabilities in programs bundled with ncpfs. Due
to a flaw in nwclient.c, utilities that use the NetWare client functions
insecurely access files with elevated privileges (CVE-2005-0013), and there is
a potentially exploitable buffer overflow in the ncplogin program
(CVE-2005-0014).

As well, an older vulnerability found by Karol Wiesek is corrected with these
new versions of ncpfs. Karol found a buffer overflow in the handling of the
'-T' option in the ncplogin and ncpmap utilities (CVE-2004-1079).



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:028
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ncpfs package";
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
if ( rpm_check( reference:"ipxutils-2.2.6-0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libncpfs2.3-2.2.6-0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libncpfs2.3-devel-2.2.6-0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ncpfs-2.2.6-0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ipxutils-2.2.6-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libncpfs2.3-2.2.6-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libncpfs2.3-devel-2.2.6-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ncpfs-2.2.6-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ncpfs-", release:"MDK10.0")
 || rpm_exists(rpm:"ncpfs-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-1079", value:TRUE);
 set_kb_item(name:"CVE-2005-0013", value:TRUE);
 set_kb_item(name:"CVE-2005-0014", value:TRUE);
}
