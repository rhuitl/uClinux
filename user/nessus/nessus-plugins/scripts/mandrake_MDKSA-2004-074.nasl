#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:074
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14172);
 script_bugtraq_id(10474, 10522, 10523);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0582", "CVE-2004-0583");
 
 name["english"] = "MDKSA-2004:074: webmin";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:074 (webmin).


Unknown vulnerability in Webmin 1.140 allows remote attackers to bypass access
control rules and gain read access to configuration information for a module.
(CVE-2004-0582)
The account lockout functionality in Webmin 1.140 does not parse certain
character strings, which allows remote attackers to conduct a brute force attack
to guess user IDs and passwords. (CVE-2004-0583)
The updated packages are patched to correct the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:074
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
if ( rpm_check( reference:"webmin-1.121-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"webmin-1.070-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"webmin-1.100-3.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"webmin-", release:"MDK10.0")
 || rpm_exists(rpm:"webmin-", release:"MDK9.1")
 || rpm_exists(rpm:"webmin-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0582", value:TRUE);
 set_kb_item(name:"CVE-2004-0583", value:TRUE);
}
