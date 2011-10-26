#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:009
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20475);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3656");
 
 name["english"] = "MDKSA-2006:009: apache2-mod_auth_pgsql";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:009 (apache2-mod_auth_pgsql).



iDefense discovered several format string vulnerabilities in the way that
mod_auth_pgsql logs information which could potentially be used by a remote
attacker to execute arbitrary code as the apache user if mod_auth_pgsql is used
for user authentication. The provided packages have been patched to prevent
this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:009
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the apache2-mod_auth_pgsql package";
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
if ( rpm_check( reference:"apache2-mod_auth_pgsql-2.0.50_2.0.2b1-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_auth_pgsql-2.0.53_2.0.2b1-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-mod_auth_pgsql-2.0.54_2.0.2b1-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"apache2-mod_auth_pgsql-", release:"MDK10.1")
 || rpm_exists(rpm:"apache2-mod_auth_pgsql-", release:"MDK10.2")
 || rpm_exists(rpm:"apache2-mod_auth_pgsql-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3656", value:TRUE);
}
