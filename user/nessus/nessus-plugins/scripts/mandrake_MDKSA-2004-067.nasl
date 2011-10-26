#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:067
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14166);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0633", "CVE-2004-0634", "CVE-2004-0635");
 
 name["english"] = "MDKSA-2004:067: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:067 (ethereal).


Three vulnerabilities were discovered in Ethereal versions prior to 0.10.5 in
the iSNS, SMB SID, and SNMP dissectors. It may be possible to make Ethereal
crash or run arbitrary code by injecting a purposefully malformed packet into
the wire or by convincing someone to read a malformed packet trace file.
These vulnerabilities have been corrected in Ethereal 0.10.5.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:067
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
if ( rpm_check( reference:"ethereal-0.10.5-0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.5-0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK10.0")
 || rpm_exists(rpm:"ethereal-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0633", value:TRUE);
 set_kb_item(name:"CVE-2004-0634", value:TRUE);
 set_kb_item(name:"CVE-2004-0635", value:TRUE);
}
