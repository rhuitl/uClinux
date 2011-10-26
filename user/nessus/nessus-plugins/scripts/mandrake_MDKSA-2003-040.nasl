#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:040
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14024);
 script_bugtraq_id(10237, 6936);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0021", "CVE-2003-0068");
 
 name["english"] = "MDKSA-2003:040: Eterm";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:040 (Eterm).


Digital Defense Inc. released a paper detailing insecurities in various terminal
emulators, including Eterm. Many of the features supported by these programs can
be abused when untrusted data is displayed on the screen. This abuse can be
anything from garbage data being displayed to the screen or a system compromise.
These issues are corrected in Eterm 0.9.2, which is already included in Mandrake
Linux 9.1.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:040
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the Eterm package";
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
if ( rpm_check( reference:"libast1-0.5-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libast1-devel-0.5-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"Eterm-0.9.2-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"Eterm-devel-0.9.2-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"Eterm-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0021", value:TRUE);
 set_kb_item(name:"CVE-2003-0068", value:TRUE);
}
