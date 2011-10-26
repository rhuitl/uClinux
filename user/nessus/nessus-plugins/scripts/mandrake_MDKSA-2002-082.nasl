#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:082-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13980);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1119");
 
 name["english"] = "MDKSA-2002:082-1: python";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:082-1 (python).


A vulnerability was discovered in python by Zack Weinberg in the way that the
execvpe() method from the os.py module uses a temporary file name. The file is
created in an unsafe manner and execvpe() tries to execute it, which can be used
by a local attacker to execute arbitrary code with the privilege of the user
running the python code that is using this method.
Update:
The previously released packages for 9.0 had an incorrect dependency on
libdb.so.2 instead of libdb.so.3. This update corrects that problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:082-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the python package";
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
if ( rpm_check( reference:"libpython2.2-2.2.1-14.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpython2.2-devel-2.2.1-14.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-2.2.1-14.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-base-2.2.1-14.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-docs-2.2.1-14.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tkinter-2.2.1-14.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"python-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1119", value:TRUE);
}
