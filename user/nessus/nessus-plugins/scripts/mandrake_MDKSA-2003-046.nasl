#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:046
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14030);
 script_bugtraq_id(7350);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0133");
 
 name["english"] = "MDKSA-2003:046: gtkhtml";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:046 (gtkhtml).


A vulnerability in GtkHTML was discovered by Alan Cox with the Evolution email
client. GtkHTML is used to handle HTML messages in Evolution and certain
malformed messages could cause Evolution to crash due to this bug.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:046
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gtkhtml package";
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
if ( rpm_check( reference:"gtkhtml-1.1.10-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtkhtml1.1_3-1.1.10-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtkhtml1.1_3-devel-1.1.10-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gtkhtml-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0133", value:TRUE);
}
