#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:070-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14820);
 script_version ("$Revision: 1.8 $");
 script_bugtraq_id(10611);
 script_cve_id("CVE-2004-0590");
 
 name["english"] = "MDKSA-2004:070-1: super-freeswan";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:070-1 (super-freeswan).


Thomas Walpuski discovered a vulnerability in the X.509 handling of
super-freeswan, openswan, strongSwan, and FreeS/WAN with the X.509 patch
applied. This vulnerability allows an attacker to make up their own Certificate
Authority that can allow them to impersonate the identity of a valid DN. As
well, another hole exists in the CA checking code that could create an endless
loop in certain instances.
Mandrakesoft encourages all users who use FreeS/WAN or super-freeswan to upgrade
to the updated packages which are patched to correct these flaws.
Update:
Due to a build error, the super-freeswan packages did not include the pluto
program. The updated packages fix this error.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:070-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the super-freeswan package";
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
if ( rpm_check( reference:"super-freeswan-1.99.8-8.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"super-freeswan-doc-1.99.8-8.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"super-freeswan-", release:"MDK10.0") )
{
 set_kb_item(name:"CVE-2004-0590", value:TRUE);
}
