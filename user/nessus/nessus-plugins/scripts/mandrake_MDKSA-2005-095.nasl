#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:095
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18404);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-1704", "CVE-2005-1705");
 
 name["english"] = "MDKSA-2005:095: gdb";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:095 (gdb).



Tavis Ormandy of the Gentoo Linux Security Audit Team discovered two
vulnerabilites in the GNU debugger. The first allows an attacker to execute
arbitrary code with the privileges of the user running gdb if they can trick
the user into loading a specially crafted executable (CVE-2005-1704).

He also discovered that gdb loads and executes the file .gdbinit in the current
directory even if the file belongs to a different user. If a user can be
tricked into running gdb in a directory with a malicious .gdbinit file, a local
attacker can exploit this to run arbitrary commands with the privileges of the
user running gdb (CVE-2005-1705).

The updated packages have been patched to correct these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:095
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gdb package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gdb-6.0-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdb-6.2-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdb-6.3-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gdb-", release:"MDK10.0")
 || rpm_exists(rpm:"gdb-", release:"MDK10.1")
 || rpm_exists(rpm:"gdb-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1704", value:TRUE);
 set_kb_item(name:"CVE-2005-1705", value:TRUE);
}
