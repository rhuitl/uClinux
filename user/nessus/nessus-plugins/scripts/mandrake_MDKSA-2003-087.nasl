#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:087
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14069);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0723");
 
 name["english"] = "MDKSA-2003:087: gkrellm";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:087 (gkrellm).


A buffer overflow was discovered in gkrellmd, the server component of the
gkrellm monitor package, in versions of gkrellm 2.1.x prior to 2.1.14. This
buffer overflow occurs while reading data from connected gkrellm clients and can
lead to possible arbitrary code execution as the user running the gkrellmd
server.
Updated packages are available for Mandrake Linux 9.1 which correct the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:087
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gkrellm package";
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
if ( rpm_check( reference:"gkrellm-2.1.7a-2.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gkrellm-devel-2.1.7a-2.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gkrellm-server-2.1.7a-2.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gkrellm-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0723", value:TRUE);
}
