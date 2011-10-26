#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:101
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14795);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2003-0559");
 
 name["english"] = "MDKSA-2004:101: webmin";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:101 (webmin).


A vulnerability in webmin was discovered by Ludwig Nussel. A temporary directory
was used in webmin, however it did not check for the previous owner of the
directory. This could allow an attacker to create the directory and place
dangerous symbolic links inside.
The updated packages are patched to prevent this problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:101
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the webmin package";
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
if ( rpm_check( reference:"webmin-1.121-4.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"webmin-1.100-3.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"webmin-", release:"MDK10.0")
 || rpm_exists(rpm:"webmin-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0559", value:TRUE);
}
