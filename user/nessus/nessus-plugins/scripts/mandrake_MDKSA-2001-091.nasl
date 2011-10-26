#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:091
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13904);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2001:091: passwd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:091 (passwd).


The default pam files for the passwd program did not include support for md5
passwords, thus any password changes or post-install added users would not have
md5 passwords.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:091
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the passwd package";
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
if ( rpm_check( reference:"passwd-0.64.1-9.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
