#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:060
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14043);
 script_bugtraq_id(7334);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0136");
 
 name["english"] = "MDKSA-2003:060: LPRng";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:060 (LPRng).


Karol Lewandowski discovered a problem with psbanner, a printer filter that
creates a PostScript format banner. psbanner creates a temporary file for
debugging purposes when it is configured as a filter, and does not check whether
or not this file already exists or is a symlink. The filter will overwrite this
file, or the file it is pointing to (if it is a symlink) with its current
environment and called arguments with the user id that LPRng is running as.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:060
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the LPRng package";
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
if ( rpm_check( reference:"LPRng-3.8.6-2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"LPRng-3.8.12-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"LPRng-", release:"MDK8.2")
 || rpm_exists(rpm:"LPRng-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0136", value:TRUE);
}
