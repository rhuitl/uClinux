#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:029
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16302);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0069");
 
 name["english"] = "MDKSA-2005:029: vim";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:029 (vim).



Javier Fernandez-Sanguino Pena discovered two vulnerabilities in scripts
included with the vim editor. The two scripts, 'tcltags' and 'vimspell.sh'
created temporary files in an insecure manner which could allow a malicious
user to execute a symbolic link attack or to create, or overwrite, arbitrary
files with the privileges of the user invoking the scripts.

The updated packages are patched to prevent this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:029
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the vim package";
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
if ( rpm_check( reference:"vim-X11-6.2-14.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-common-6.2-14.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-enhanced-6.2-14.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-minimal-6.2-14.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-X11-6.3-5.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-common-6.3-5.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-enhanced-6.3-5.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-minimal-6.3-5.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"vim-", release:"MDK10.0")
 || rpm_exists(rpm:"vim-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0069", value:TRUE);
}
