#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18472);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0175");

 name["english"] = "RHSA-2005-495: rsh";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated rsh packages that fix a theoretical security issue are now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team

  The rsh package contains a set of programs that allow users to run
  commands on remote machines, login to other machines, and copy files
  between machines, using the rsh, rlogin, and rcp commands. All three of
  these commands use rhosts-style authentication.

  The rcp protocol allows a server to instruct a client to write to arbitrary
  files outside of the current directory. This could potentially cause a
  security issue if a user uses rcp to copy files from a malicious server.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-0175 to this issue.

  All users of rsh should upgrade to these updated packages, which resolve
  these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-495.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the rsh packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"rsh-0.17-18.AS21.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsh-server-0.17-18.AS21.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"rsh-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0175", value:TRUE);
}

set_kb_item(name:"RHSA-2005-495", value:TRUE);
