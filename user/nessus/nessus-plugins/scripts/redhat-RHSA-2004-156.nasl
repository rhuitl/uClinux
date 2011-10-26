#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12485);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0182");

 name["english"] = "RHSA-2004-156: mailman";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated mailman package that closes a DoS vulnerability in mailman
  introduced by RHSA-2004:019 is now available.

  Mailman is a mailing list manager.

  On February 19 2004, Red Hat issued security erratum RHSA-2004:019 to
  correct a DoS (Denial of Service) vulnerability where an attacker could
  send a carefully-crafted message and cause mailman to crash.

  Matthew Saltzman discovered a flaw in our original patch intended to
  correct this vulnerability. This flaw can cause mailman to crash if it
  receives an email destined for a list with an empty subject field. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2004-0182 to this issue.

  Users of Mailman are advised to upgrade to these updated packages, which
  include an updated patch and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-156.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mailman packages";
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
if ( rpm_check( reference:"mailman-2.0.13-6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mailman-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0182", value:TRUE);
}

set_kb_item(name:"RHSA-2004-156", value:TRUE);
