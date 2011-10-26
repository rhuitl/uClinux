#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:024
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14123);
 script_bugtraq_id(9952);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0176", "CVE-2004-0365", "CVE-2004-0367");
 
 name["english"] = "MDKSA-2004:024: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:024 (ethereal).


A number of serious issues have been discovered in versions of Ethereal prior to
0.10.2. Stefan Esser discovered thirteen buffer overflows in the NetFlow, IGAP,
EIGRP, PGM, IrDA, BGP, ISUP, and TCAP dissectors. Jonathan Heusser discovered
that a carefully-crafted RADIUS packet could cause Ethereal to crash. It was
also found that a zero-length Presentation protocol selector could make Ethereal
crash. Finally, a corrupt color filter file could cause a segmentation fault. It
is possible, through the exploitation of some of these vulnerabilities, to cause
Ethereal to crash or run arbitrary code by injecting a malicious, malformed
packet onto the wire, by convincing someone to read a malformed packet trace
file, or by creating a malformed color filter file.
The updated packages bring Ethereal to version 0.10.3 which is not vulnerable to
these issues.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:024
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
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
if ( rpm_check( reference:"ethereal-0.10.3-0.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.3-0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK9.1")
 || rpm_exists(rpm:"ethereal-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0176", value:TRUE);
 set_kb_item(name:"CVE-2004-0365", value:TRUE);
 set_kb_item(name:"CVE-2004-0367", value:TRUE);
}
