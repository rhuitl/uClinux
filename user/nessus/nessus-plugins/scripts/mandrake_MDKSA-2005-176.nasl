#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:176
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20429);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3042");
 
 name["english"] = "MDKSA-2005:176: webmin";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:176 (webmin).



Miniserv.pl in Webmin 1.220, when 'full PAM conversations' is enabled, allows
remote attackers to bypass authentication by spoofing session IDs via certain
metacharacters (line feed or carriage return).

The updated packages have been patched to correct this issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:176
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the webmin package";
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
if ( rpm_check( reference:"webmin-1.220-9.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"webmin-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3042", value:TRUE);
}
