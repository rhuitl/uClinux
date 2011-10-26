#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:108
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15522);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0778");
 
 name["english"] = "MDKSA-2004:108: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:108 (cvs).


iDEFENSE discovered a flaw in CVS versions prior to 1.1.17 in an undocumented
switch implemented in CVS' history command. The -X switch specifies the name of
the history file which allows an attacker to determine whether arbitrary system
files and directories exist and whether or not the CVS process has access to
them.
This flaw has been fixed in CVS version 1.1.17.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:108
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cvs package";
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
if ( rpm_check( reference:"cvs-1.11.17-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.17-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cvs-", release:"MDK10.0")
 || rpm_exists(rpm:"cvs-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0778", value:TRUE);
}
