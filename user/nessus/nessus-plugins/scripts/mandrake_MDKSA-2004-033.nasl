#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:033
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14132);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0372");
 
 name["english"] = "MDKSA-2004:033: xine-ui";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:033 (xine-ui).


Shaun Colley discovered a temporary file vulnerability in the xine-check script
packaged in xine-ui. This problem could allow local attackers to overwrite
arbitrary files with the privileges of the user invoking the script.
The updated packages change the location of where temporary files are written to
prevent this attack.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:033
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xine-ui package";
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
if ( rpm_check( reference:"xine-ui-0.9.23-3.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-ui-aa-0.9.23-3.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-ui-fb-0.9.23-3.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-ui-0.9.22-5.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-ui-aa-0.9.22-5.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-ui-fb-0.9.22-5.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"xine-ui-", release:"MDK10.0")
 || rpm_exists(rpm:"xine-ui-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0372", value:TRUE);
}
