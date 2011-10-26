#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:079
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21285);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1931");
 
 name["english"] = "MDKSA-2006:079: ruby";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:079 (ruby).



A vulnerability in how ruby's HTTP module uses blocking sockets was reported by
Yukihiro Matsumoto. By sending large amounts of data to a server application
using this module, a remote attacker could exploit it to render the application
unusable and not respond to other client requests. The updated packages have
been patched to fix this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:079
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ruby package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ruby-1.8.2-6.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.2-6.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-doc-1.8.2-6.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-tk-1.8.2-6.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-1.8.2-7.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.2-7.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-doc-1.8.2-7.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-tk-1.8.2-7.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ruby-", release:"MDK10.2")
 || rpm_exists(rpm:"ruby-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-1931", value:TRUE);
}
