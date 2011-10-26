#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:128
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15650);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0755", "CVE-2004-0983");
 
 name["english"] = "MDKSA-2004:128: ruby";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:128 (ruby).



Andres Salomon noticed a problem with the CGI session management in Ruby. The
CGI:Session's FileStore implementations store session information in an
insecure manner by just creating files and ignoring permission issues
(CVE-2004-0755).

The ruby developers have corrected a problem in the ruby CGI module that can be
triggered remotely and cause an inifinite loop on the server (CVE-2004-0983).

The updated packages are patched to prevent these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:128
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ruby package";
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
if ( rpm_check( reference:"ruby-1.8.1-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.1-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-doc-1.8.1-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-tk-1.8.1-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-1.8.1-4.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.1-4.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-doc-1.8.1-4.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-tk-1.8.1-4.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-1.8.0-4.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.0-4.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-doc-1.8.0-4.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-tk-1.8.0-4.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ruby-", release:"MDK10.0")
 || rpm_exists(rpm:"ruby-", release:"MDK10.1")
 || rpm_exists(rpm:"ruby-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0755", value:TRUE);
 set_kb_item(name:"CVE-2004-0983", value:TRUE);
}
