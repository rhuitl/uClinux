#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:188
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20433);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2965");
 
 name["english"] = "MDKSA-2005:188: graphviz";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:188 (graphviz).



Javier Fern ndez-Sanguino Pe a discovered insecure temporary file creation in
graphviz, a rich set of graph drawing tools, that can be exploited to overwrite
arbitrary files by a local attacker.

The updated packages have been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:188
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the graphviz package";
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
if ( rpm_check( reference:"graphviz-2.2-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgraphviz7-2.2-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgraphviz7-devel-2.2-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgraphviztcl7-2.2-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgraphviztcl7-devel-2.2-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"graphviz-2.2.1-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgraphviz7-2.2.1-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgraphviz7-devel-2.2.1-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgraphviztcl7-2.2.1-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgraphviztcl7-devel-2.2.1-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"graphviz-", release:"MDK10.2")
 || rpm_exists(rpm:"graphviz-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-2965", value:TRUE);
}
