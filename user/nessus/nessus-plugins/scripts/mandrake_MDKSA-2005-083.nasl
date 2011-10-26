#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:083
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18237);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-1456", "CVE-2005-1457", "CVE-2005-1458", "CVE-2005-1459", "CVE-2005-1460", "CVE-2005-1461", "CVE-2005-1462", "CVE-2005-1463", "CVE-2005-1464", "CVE-2005-1465", "CVE-2005-1466", "CVE-2005-1467", "CVE-2005-1468", "CVE-2005-1469", "CVE-2005-1470");
 
 name["english"] = "MDKSA-2005:083: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:083 (ethereal).



A number of vulnerabilities were discovered in previous version of Ethereal
that have been fixed in the 0.10.11 release, including:

- The ANSI A and DHCP dissectors are vulnerable to format string
vulnerabilities.

- The DISTCC, FCELS, SIP, ISIS, CMIP, CMP, CMS, CRMF, ESS, OCSP, PKIX1Explitit,
PKIX Qualified, X.509, Q.931, MEGACO, NCP, ISUP, TCAP and Presentation
dissectors are vulnerable to buffer overflows.

- The KINK, WSP, SMB Mailslot, H.245, MGCP, Q.931, RPC, GSM and SMB NETLOGON
dissectors are vulnerable to pointer handling errors.

- The LMP, KINK, MGCP, RSVP, SRVLOC, EIGRP, MEGACO, DLSw, NCP and L2TP
dissectors are vulnerable to looping problems.

- The Telnet and DHCP dissectors could abort.

- The TZSP, Bittorrent, SMB, MGCP and ISUP dissectors could cause a
segmentation fault.

- The WSP, 802.3 Slow protocols, BER, SMB Mailslot, SMB, NDPS, IAX2, RADIUS,
SMB PIPE, MRDISC and TCAP dissectors could throw assertions.

- The DICOM, NDPS and ICEP dissectors are vulnerable to memory handling errors.

- The GSM MAP, AIM, Fibre Channel,SRVLOC, NDPS, LDAP and NTLMSSP dissectors
could terminate abnormallly.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:083
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ethereal-0.10.11-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-tools-0.10.11-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libethereal0-0.10.11-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tethereal-0.10.11-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.11-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-tools-0.10.11-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libethereal0-0.10.11-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tethereal-0.10.11-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK10.1")
 || rpm_exists(rpm:"ethereal-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1456", value:TRUE);
 set_kb_item(name:"CVE-2005-1457", value:TRUE);
 set_kb_item(name:"CVE-2005-1458", value:TRUE);
 set_kb_item(name:"CVE-2005-1459", value:TRUE);
 set_kb_item(name:"CVE-2005-1460", value:TRUE);
 set_kb_item(name:"CVE-2005-1461", value:TRUE);
 set_kb_item(name:"CVE-2005-1462", value:TRUE);
 set_kb_item(name:"CVE-2005-1463", value:TRUE);
 set_kb_item(name:"CVE-2005-1464", value:TRUE);
 set_kb_item(name:"CVE-2005-1465", value:TRUE);
 set_kb_item(name:"CVE-2005-1466", value:TRUE);
 set_kb_item(name:"CVE-2005-1467", value:TRUE);
 set_kb_item(name:"CVE-2005-1468", value:TRUE);
 set_kb_item(name:"CVE-2005-1469", value:TRUE);
 set_kb_item(name:"CVE-2005-1470", value:TRUE);
}
