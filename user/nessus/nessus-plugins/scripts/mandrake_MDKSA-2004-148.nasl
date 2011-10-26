#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:148
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15956);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2003-0856");
 
 name["english"] = "MDKSA-2004:148: iproute2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:148 (iproute2).



Herbert Xu discovered that iproute can accept spoofed messages sent via the                      
kernel netlink interface by other users on the local machine. This could lead                    
to a local Denial of Service attack.                                                             

The updated packages have been patched to prevent this problem.                                  



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:148
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the iproute2 package";
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
if ( rpm_check( reference:"iproute2-2.4.7-11.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"iproute2-2.4.7-11.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"iproute2-", release:"MDK10.0")
 || rpm_exists(rpm:"iproute2-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0856", value:TRUE);
}
