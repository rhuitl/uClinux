#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:013
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20479);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "MDKSA-2006:013: kolab-resource-handlers";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:013 (kolab-resource-handlers).



A problem exists in how the Kolab Server transports emails bigger than 8KB in
size and if a dot ('.') character exists in the wrong place. If these
conditions are met, kolabfilter will double this dot and a modified email will
be delivered, which could lead to broken clear-text signatures or broken
attachments. The updated packages have been patched to correct these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:013
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kolab-resource-handlers package";
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
if ( rpm_check( reference:"kolab-resource-handlers-0.4.1-0.20050811.2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
