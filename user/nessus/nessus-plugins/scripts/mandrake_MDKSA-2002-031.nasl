#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:031
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13937);
 script_bugtraq_id(4266);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0435");
 
 name["english"] = "MDKSA-2002:031: fileutils";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:031 (fileutils).


Wojciech Purczynski reported a race condition in some utilities in the GNU
fileutils package that may cause root to delete the entire filesystem. This only
affects version 4.1 stable and 4.1.6 development versions, and the authors have
fixed this in the latest development version.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:031
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the fileutils package";
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
if ( rpm_check( reference:"fileutils-4.1-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fileutils-4.1.5-4.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"fileutils-", release:"MDK8.1")
 || rpm_exists(rpm:"fileutils-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-0435", value:TRUE);
}
