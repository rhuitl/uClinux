#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:005
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16135);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0946");
 
 name["english"] = "MDKSA-2005:005: nfs-utils";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:005 (nfs-utils).



Arjan van de Ven discovered a buffer overflow in rquotad on 64bit
architectures; an improper integer conversion could lead to a buffer overflow.
An attacker with access to an NFS share could send a specially crafted request
which could then lead to the execution of arbitrary code.

The updated packages are provided to prevent this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:005
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the nfs-utils package";
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
if ( rpm_check( reference:"nfs-utils-1.0.6-2.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nfs-utils-clients-1.0.6-2.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nfs-utils-1.0.6-2.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nfs-utils-clients-1.0.6-2.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nfs-utils-1.0.5-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nfs-utils-clients-1.0.5-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"nfs-utils-", release:"MDK10.0")
 || rpm_exists(rpm:"nfs-utils-", release:"MDK10.1")
 || rpm_exists(rpm:"nfs-utils-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0946", value:TRUE);
}
