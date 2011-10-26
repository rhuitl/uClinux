#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12372);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2002-1337");

 name["english"] = "RHSA-2003-074: sendmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Sendmail packages are available to fix a vulnerability that
  may allow remote attackers to gain root privileges by sending a
  carefully crafted message.

  [Updated March 18 2003]
  Added packages for Red Hat Enterprise Linux ES and Red Hat Enterprise Linux
  WS.

  Sendmail is a widely used Mail Transport Agent (MTA) which is included
  in all Red Hat Enterprise Linux distributions.

  During a code audit of Sendmail by ISS, a critical vulnerability was
  uncovered that affects unpatched versions of Sendmail prior to version
  8.12.8. A remote attacker can send a carefully crafted email message
  which, when processed by sendmail, causes arbitrary code to be
  executed as root.

  We are advised that a proof-of-concept exploit is known to exist, but
  is not believed to be in the wild.

  Since this is a message-based vulnerability, MTAs other than Sendmail
  may pass on the carefully crafted message. This means that unpatched
  versions of Sendmail inside a network could still be at risk even if
  they do not accept external connections directly.

  All users are advised to update to these erratum packages which contain
  a backported patch to correct this vulnerability.

  Red Hat would like to thank Eric Allman for his assistance with this
  vulnerability.




Solution : http://rhn.redhat.com/errata/RHSA-2003-074.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sendmail packages";
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
if ( rpm_check( reference:"sendmail-8.11.6-24.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.11.6-24.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.11.6-24.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.11.6-24.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"sendmail-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1337", value:TRUE);
}

set_kb_item(name:"RHSA-2003-074", value:TRUE);
