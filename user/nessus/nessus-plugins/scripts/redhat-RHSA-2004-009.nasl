#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12449);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0966");

 name["english"] = "RHSA-2004-009: elm";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated elm packages are now available that fix a buffer overflow
  vulnerability in the \'frm\' command.

  Elm is a terminal mode email user agent. The frm command is provided as
  part of the Elm packages and gives a summary list of the sender and subject
  of selected messages in a mailbox or folder.

  A buffer overflow vulnerability was found in the frm command. An attacker
  could create a message with an overly long Subject line such that when the
  frm command is run by a victim arbitrary code is executed. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2003-0966 to this issue.

  Users of the frm command should update to these erratum packages, which
  contain a backported security patch that corrects this issue.

  Red Hat would like to thank Paul Rubin for discovering and disclosing this
  issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-009.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the elm packages";
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
if ( rpm_check( reference:"elm-2.5.6-4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"elm-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0966", value:TRUE);
}

set_kb_item(name:"RHSA-2004-009", value:TRUE);
