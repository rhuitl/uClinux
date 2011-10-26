#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:157
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19912);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "MDKSA-2005:157: smb4k";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:157 (smb4k).



A severe security issue has been discovered in Smb4K. By linking a simple
text file FILE to /tmp/smb4k.tmp or /tmp/sudoers, an attacker could get
access to the full contents of the /etc/super.tab or /etc/sudoers file,
respectively, because Smb4K didn't check for the existance of these files
before writing any contents. When using super, the attack also resulted in /
etc/super.tab being a symlink to FILE.

Affected are all versions of the 0.4, 0.5, and 0.6 series of Smb4K.

The updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:157
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the smb4k package";
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
if ( rpm_check( reference:"smb4k-0.4.0-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"smb4k-0.5.1-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
