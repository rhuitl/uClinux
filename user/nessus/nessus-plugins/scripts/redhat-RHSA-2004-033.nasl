#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12455);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0006", "CVE-2004-0007", "CVE-2004-0008");

 name["english"] = "RHSA-2004-033: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Gaim packages that fix a number of serious vulnerabilities are now
  available.

  Gaim is an instant messenger client that can handle multiple protocols.

  Stefan Esser audited the Gaim source code and found a number of bugs that
  have security implications. Due to the nature of instant messaging many of
  these bugs require man-in-the-middle attacks between client and server.
  However at least one of the buffer overflows could be exploited by an
  attacker sending a carefully-constructed malicious message through a
  server.

  The issues include:

  Multiple buffer overflows that affect versions of Gaim 0.75 and earlier.
  1) When parsing cookies in a Yahoo web connection, 2) YMSG protocol
  overflows parsing the Yahoo login webpage, 3) a YMSG packet overflow, 4)
  flaws in the URL parser, and 5) flaws in HTTP Proxy connect. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0006 to these issues.

  A buffer overflow in Gaim 0.74 and earlier in the Extract Info
  Field Function used for MSN and YMSG protocol handlers. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-0007 to this issue.

  An integer overflow in Gaim 0.74 and earlier, when allocating
  memory for a directIM packet results in heap overflow.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-0008 to this issue.

  All users of Gaim should upgrade to these erratum packages, which contain
  backported security patches correcting these issues.

  Red Hat would like to thank Steffan Esser for finding and reporting these
  issues and Jacques A. Vidrine for providing initial patches.




Solution : http://rhn.redhat.com/errata/RHSA-2004-033.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gaim packages";
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
if ( rpm_check( reference:"gaim-0.75-3.2.0", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gaim-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0006", value:TRUE);
 set_kb_item(name:"CVE-2004-0007", value:TRUE);
 set_kb_item(name:"CVE-2004-0008", value:TRUE);
}

set_kb_item(name:"RHSA-2004-033", value:TRUE);
