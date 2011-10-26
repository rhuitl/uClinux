#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:048
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14032);
 script_bugtraq_id(7121);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0165");
 
 name["english"] = "MDKSA-2003:048: eog";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:048 (eog).


A vulnerability was discovered in the Eye of GNOME (EOG) program, version 2.2.0
and earlier, that is used for displaying graphics. A carefully crafted filename
passed to eog could lead to the execution of arbitrary code as the user
executing eog.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:048
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the eog package";
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
if ( rpm_check( reference:"eog-1.0.2-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"eog-2.2.0-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"eog-", release:"MDK9.0")
 || rpm_exists(rpm:"eog-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0165", value:TRUE);
}
