#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:060
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14159);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2004:060: ksymoops";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:060 (ksymoops).


Geoffrey Lee discovered a problem with the ksymoops-gznm script distributed with
Mandrakelinux. The script fails to do proper checking when copying a file to the
/tmp directory. Because of this, a local attacker can setup a symlink to point
to a file that they do not have permission to remove. The problem is difficult
to exploit because someone with root privileges needs to run ksymoops on a
particular module for which a symlink for the same filename already exists.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:060
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ksymoops package";
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
if ( rpm_check( reference:"ksymoops-2.4.9-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ksymoops-2.4.8-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ksymoops-2.4.9-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
