#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:002
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14102);
 script_bugtraq_id(9248, 9249);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-1012", "CVE-2003-1013");
 
 name["english"] = "MDKSA-2004:002: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:002 (ethereal).


Two vulnerabilities were discovered in versions of Ethereal prior to 0.10.0 that
can be exploited to make Ethereal crash by injecting malformed packets onto the
wire or by convincing a user to read a malformed packet trace file. The first
vulnerability is in the SMB dissector and the second is in the Q.391 dissector.
It is not known whether or not these issues could lead to the execution of
arbitrary code.
The updated packages provide Ethereal 0.10.0 which is not vulnerable to these
issues.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:002
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
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
if ( rpm_check( reference:"ethereal-0.10.0a-0.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.0a-0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK9.1")
 || rpm_exists(rpm:"ethereal-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-1012", value:TRUE);
 set_kb_item(name:"CVE-2003-1013", value:TRUE);
}
