#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:075
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14173);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0700");
 
 name["english"] = "MDKSA-2004:075: mod_ssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:075 (mod_ssl).


Ralf S. Engelschall found a remaining risky call to ssl_log while reviewing code
for another issue reported by Virulent. The updated packages are patched to
correct the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:075
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mod_ssl package";
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
if ( rpm_check( reference:"mod_ssl-2.8.16-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.12-8.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.15-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mod_ssl-", release:"MDK10.0")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK9.1")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0700", value:TRUE);
}
