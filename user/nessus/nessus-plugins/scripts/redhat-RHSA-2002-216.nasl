#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12327);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1174", "CVE-2002-1175");

 name["english"] = "RHSA-2002-216: fetchmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Fetchmail packages are available for Red Hat Linux Advanced Server
  which close a remotely-exploitable vulnerability in unpatched versions of
  Fetchmail prior to 6.1.0.

  Fetchmail is a remote mail retrieval and forwarding utility intended for
  use over on-demand TCP/IP links such as SLIP and PPP connections. Two bugs
  have been found in the header parsing code in versions of Fetchmail prior
  to 6.1.0.

  The first bug allows a remote attacker to crash Fetchmail by sending a
  carefully crafted DNS packet. The second bug allows a remote attacker to
  carefully craft an email in such a way that when it is parsed by Fetchmail
  a heap overflow occurs, allowing remote arbitrary code execution.

  Both of these bugs are only exploitable if Fetchmail is being used in
  multidrop mode (using the "multiple-local-recipients" feature).

  All users of Fetchmail are advised to upgrade to the errata packages
  containing a backported fix which is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2002-216.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the fetchmail packages";
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
if ( rpm_check( reference:"fetchmail-5.9.0-20", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-5.9.0-20", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"fetchmail-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1174", value:TRUE);
 set_kb_item(name:"CVE-2002-1175", value:TRUE);
}

set_kb_item(name:"RHSA-2002-216", value:TRUE);
