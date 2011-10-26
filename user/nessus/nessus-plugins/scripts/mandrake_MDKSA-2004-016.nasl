#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:016
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14116);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2004:016: mtools";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:016 (mtools).


Sebastian Krahmer found that the mformat program, when installed suid root, can
create any file with 0666 permissions as root, and that it also does not drop
privileges when reading local configuration files.
The updated packages remove the suid bit from mformat.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:016
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mtools package";
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
if ( rpm_check( reference:"mtools-3.9.9-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
