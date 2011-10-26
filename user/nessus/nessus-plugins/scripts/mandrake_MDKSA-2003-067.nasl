#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:067
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14050);
 script_bugtraq_id(7493, 7494, 7495);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0356", "CVE-2003-0357");
 
 name["english"] = "MDKSA-2003:067: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:067 (ethereal).


Several vulnerabilities in ethereal were discovered by Timo Sirainen. Integer
overflows were found in the Mount and PPP dissectors, as well as one-byte buffer
overflows in the AIM, GIOP Gryphon, OSPF, PPTP, Quake, Quake2, Quake3, Rsync,
SMB, SMPP, and TSP dissectors. These vulnerabilties were corrected in ethereal
0.9.12.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:067
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
if ( rpm_check( reference:"ethereal-0.9.12-1.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0356", value:TRUE);
 set_kb_item(name:"CVE-2003-0357", value:TRUE);
}
