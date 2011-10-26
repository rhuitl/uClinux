#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:068
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14051);
 script_bugtraq_id(7872);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0367", "CVE-1999-1332");
 
 name["english"] = "MDKSA-2003:068: gzip";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:068 (gzip).


A vulnerability exists in znew, a script included with gzip, that would create
temporary files without taking precautions to avoid a symlink attack. Patches
have been applied to make use of mktemp to generate unique filenames, and
properly make use of noclobber in the script. Likewise, a fix for gzexe which
had been applied previously was incomplete. It has been fixed to make full use
of mktemp everywhere a temporary file is created.
The znew problem was initially reported by Michal Zalewski and was again
reported more recently to Debian by Paul Szabo.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:068
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gzip package";
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
if ( rpm_check( reference:"gzip-1.2.4a-11.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gzip-1.2.4a-11.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gzip-1.2.4a-11.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gzip-", release:"MDK8.2")
 || rpm_exists(rpm:"gzip-", release:"MDK9.0")
 || rpm_exists(rpm:"gzip-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0367", value:TRUE);
 set_kb_item(name:"CVE-1999-1332", value:TRUE);
}
