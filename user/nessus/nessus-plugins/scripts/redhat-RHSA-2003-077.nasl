#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12373);
 script_version ("$Revision: 1.6 $");
 if (NASL_LEVEL >= 2191 ) script_cve_id("CVE-2003-0159", "CVE-2003-0356", "CVE-2003-0357", "CVE-2003-0428", "CVE-2003-0429", "CVE-2003-0430", "CVE-2003-0431", "CVE-2003-0432", "CVE-2003-0081");

 name["english"] = "RHSA-2003-077: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Ethereal packages fixing a number of remotely exploitable security
  issues are now available.

  Ethereal is a package designed for monitoring network traffic.

  A number of security issues affect Ethereal. By exploiting these issues it
  may be possible to make Ethereal crash or run arbitrary code by injecting a
  purposefully malformed packet onto the wire, or by convincing someone to
  read a malformed packet trace file.

  Ethereal 0.9.9 and earlier allows remote attackers to cause a denial
  of service (crash) and possibly execute arbitrary code via carefully
  crafted SOCKS packets. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2003-0081 to this issue.

  A heap-based buffer overflow exists in the NTLMSSP code for Ethereal
  0.9.9 and earlier. (CVE-2003-0159)

  Multiple off-by-one vulnerabilities exist in Ethereal 0.9.11 and earlier in
  the AIM, GIOP Gryphon, OSPF, PPTP, Quake, Quake2, Quake3, Rsync, SMB, SMPP,
  and TSP dissectors, which do not properly use the tvb_get_nstringz and
  tvb_get_nstringz0 functions. (CVE-2003-0356)

  Multiple integer overflow vulnerabilities exist in Ethereal 0.9.11 and
  earlier in the Mount and PPP dissectors. (CVE-2003-0357)

  A vulnerability in the DCERPC dissector exists in Ethereal 0.9.12 and
  earlier, allowing remote attackers to cause a denial of service (memory
  consumption) via a certain NDR string. (CVE-2003-0428)

  A possible buffer overflow vulnerability exists in Ethereal 0.9.12 and
  earlier, caused by invalid IPv4 or IPv6 prefix lengths and possibly
  triggering a buffer overflow. (CVE-2003-0429)

  A vulnerability exists in Ethereal 0.9.12 and earlier, allowing remote
  attackers to cause a denial of service (crash) via an invalid ASN.1 value.
  (CVE-2003-0430)

  The tvb_get_nstringz0 function in Ethereal 0.9.12 and earlier does not
  properly handle a zero-length buffer size. (CVE-2003-0431)

  Ethereal 0.9.12 and earlier does not handle certain strings properly in the
  BGP, WTP, DNS, 802.11, ISAKMP, WSP, CLNP, ISIS, and RMI dissectors.
  (CVE-2003-0432)

  Users of Ethereal should update to these erratum packages containing
  Ethereal version 0.9.13, which are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2003-077.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ethereal-0.9.13-1.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.9.13-1.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ethereal-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0159", value:TRUE);
 set_kb_item(name:"CVE-2003-0356", value:TRUE);
 set_kb_item(name:"CVE-2003-0357", value:TRUE);
 set_kb_item(name:"CVE-2003-0428", value:TRUE);
 set_kb_item(name:"CVE-2003-0429", value:TRUE);
 set_kb_item(name:"CVE-2003-0430", value:TRUE);
 set_kb_item(name:"CVE-2003-0431", value:TRUE);
 set_kb_item(name:"CVE-2003-0432", value:TRUE);
 set_kb_item(name:"CVE-2003-0081", value:TRUE);
}

set_kb_item(name:"RHSA-2003-077", value:TRUE);
