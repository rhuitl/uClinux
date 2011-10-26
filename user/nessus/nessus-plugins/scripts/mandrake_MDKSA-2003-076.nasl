#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:076
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14059);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0252");
 
 name["english"] = "MDKSA-2003:076: nfs-utils";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:076 (nfs-utils).


An off-by-one buffer overflow was found in the logging code in nfs-utils when
adding a newline to the string being logged. This could allow an attacker to
execute arbitrary code or cause a DoS (Denial of Service) on the server by
sending certain RPC requests.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:076
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the nfs-utils package";
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
if ( rpm_check( reference:"nfs-utils-0.3.3-3.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nfs-utils-clients-0.3.3-3.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nfs-utils-1.0.1-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nfs-utils-clients-1.0.1-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nfs-utils-1.0.1-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nfs-utils-clients-1.0.1-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"nfs-utils-", release:"MDK8.2")
 || rpm_exists(rpm:"nfs-utils-", release:"MDK9.0")
 || rpm_exists(rpm:"nfs-utils-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0252", value:TRUE);
}
