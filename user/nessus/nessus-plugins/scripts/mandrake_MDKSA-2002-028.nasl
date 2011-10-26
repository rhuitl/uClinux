#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:028
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13935);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:028: sudo";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:028 (sudo).


A problem was discovered by fc, with further research by Global InterSec, in the
sudo program with the password prompt parameter (-p). Sudo can be tricked into
allocating less memory than it should for the prompt and in certain conditions
it is possible to exploit this flaw to corrupt the heap in such a way that could
be used to execute arbitary commands. Because sudo is generally suid root, this
can lead to an elevation of privilege for local users.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:028
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sudo package";
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
if ( rpm_check( reference:"sudo-1.6.4-3.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.4-3.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.4-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.4-3.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.4-3.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
