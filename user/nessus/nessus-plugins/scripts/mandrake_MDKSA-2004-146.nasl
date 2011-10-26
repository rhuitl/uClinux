#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:146
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15919);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1014");
 
 name["english"] = "MDKSA-2004:146: nfs-utils";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:146 (nfs-utils).



SGI developers discovered a remote DoS (Denial of Service) condition in the NFS
statd server. rpc.statd did not ignore the 'SIGPIPE' signal which would cause
it to shutdown if a misconfigured or malicious peer terminated the TCP
connection prematurely.

The updated packages have been patched to prevent this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:146
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
if ( rpm_check( reference:"nfs-utils-1.0.6-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nfs-utils-clients-1.0.6-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nfs-utils-1.0.6-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nfs-utils-clients-1.0.6-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nfs-utils-1.0.5-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nfs-utils-clients-1.0.5-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"nfs-utils-", release:"MDK10.0")
 || rpm_exists(rpm:"nfs-utils-", release:"MDK10.1")
 || rpm_exists(rpm:"nfs-utils-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-1014", value:TRUE);
}
