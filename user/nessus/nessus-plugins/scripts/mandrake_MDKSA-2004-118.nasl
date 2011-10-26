#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:118
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15598);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "MDKSA-2004:118: perl-Archive-Zip";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:118 (perl-Archive-Zip).



Recently, it was noticed that several antivirus programs miss viruses that are
contained in ZIP archives with manipulated directory data. The global archive
directory of these ZIP file have been manipulated to indicate zero file sizes.

Archive::Zip produces files of zero length when decompressing this type of ZIP
file. This causes AV products that use Archive::ZIP to fail to detect viruses
in manipulated ZIP archives. One of these products is amavisd-new.

The updated packages are patched to fix this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:118
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the perl-Archive-Zip package";
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
if ( rpm_check( reference:"perl-Archive-Zip-1.14-1.0.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
