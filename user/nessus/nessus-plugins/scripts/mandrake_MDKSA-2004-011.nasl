#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:011-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14111);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(9442);
 script_cve_id("CVE-2003-0924");
 
 name["english"] = "MDKSA-2004:011-1: netpbm";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:011-1 (netpbm).


A number of temporary file bugs have been found in versions of NetPBM. These
could allow a local user the ability to overwrite or create files as a different
user who happens to run one of the the vulnerable utilities.
Update:
The patch applied made some calls to the mktemp utility with an incorrect
parameter which prevented mktemp from creating temporary files in some scripts.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:011-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the netpbm package";
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
if ( rpm_check( reference:"libnetpbm9-9.24-8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnetpbm9-devel-9.24-8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-9.24-8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnetpbm9-9.24-7.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libnetpbm9-devel-9.24-7.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-9.24-7.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"netpbm-", release:"MDK10.0")
 || rpm_exists(rpm:"netpbm-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0924", value:TRUE);
}
