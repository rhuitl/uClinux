#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:054
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14153);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0488");
 
 name["english"] = "MDKSA-2004:054: mod_ssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:054 (mod_ssl).


A stack-based buffer overflow exists in the ssl_util_uuencode_binary function in
ssl_engine_kernel.c in mod_ssl for Apache 1.3.x. When mod_ssl is configured to
trust the issuing CA, a remote attacker may be able to execute arbitrary code
via a client certificate with a long subject DN.
The provided packages are patched to prevent this problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:054
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
if ( rpm_check( reference:"mod_ssl-2.8.16-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.12-8.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.15-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mod_ssl-", release:"MDK10.0")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK9.1")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0488", value:TRUE);
}
