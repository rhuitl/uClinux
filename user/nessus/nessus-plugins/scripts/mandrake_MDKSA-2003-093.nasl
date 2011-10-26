#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:093
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14075);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0541");
 
 name["english"] = "MDKSA-2003:093: gtkhtml";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:093 (gtkhtml).


Alan Cox discovered that certain malformed messages could cause the Evolution
mail component to crash due to a null pointer dereference in the GtkHTML
library, versions prior to 1.1.0.
The updated package provides a patched version of GtkHTML; versions of Mandrake
Linux more recent than 9.0 do not require this fix as they already come with
version 1.1.0.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:093
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
if ( rpm_check( reference:"libgtkhtml20-1.0.4-4.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtkhtml20-devel-1.0.4-4.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtkhtml-1.0.4-4.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gtkhtml-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0541", value:TRUE);
}
