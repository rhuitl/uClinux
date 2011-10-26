#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:008
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14108);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0008");
 script_bugtraq_id(9263, 9423);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0989", "CVE-2003-1029", "CVE-2004-0055", "CVE-2004-0057");
 
 name["english"] = "MDKSA-2004:008: tcpdump";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:008 (tcpdump).


A number of vulnerabilities were discovered in tcpdump versions prior to 3.8.1
that, if fed a maliciously crafted packet, could be exploited to crash tcpdump
or potentially execute arbitrary code with the privileges of the user running
tcpdump. These vulnerabilities include:
An infinite loop and memory consumption processing L2TP packets (CVE-2003-1029).
Infinite loops in processing ISAKMP packets (CVE-2003-0989, CVE-2004-0057).
A segmentation fault caused by a RADIUS attribute with a large length value
(CVE-2004-0055).
The updated packages are patched to correct these problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:008
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tcpdump package";
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
if ( rpm_check( reference:"tcpdump-3.7.2-2.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.7.2-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"tcpdump-", release:"MDK9.1")
 || rpm_exists(rpm:"tcpdump-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0989", value:TRUE);
 set_kb_item(name:"CVE-2003-1029", value:TRUE);
 set_kb_item(name:"CVE-2004-0055", value:TRUE);
 set_kb_item(name:"CVE-2004-0057", value:TRUE);
}
