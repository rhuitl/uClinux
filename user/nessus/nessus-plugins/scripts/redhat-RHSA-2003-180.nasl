#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12398);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0178");

 name["english"] = "RHSA-2003-180: sharutils";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated packages for sharutils which fix potential privilege escalation
  using the uudecode utility are available.

  The sharutils package contains a set of tools for encoding and decoding
  packages of files in binary or text format.

  The uudecode utility creates an output file without checking to see if
  it was about to write to a symlink or a pipe. If a user uses uudecode to
  extract data into open shared directories, such as /tmp, this vulnerability
  could be used by a local attacker to overwrite files or lead to privilege
  escalation.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2002-0178 to this issue.

  Users are advised to upgrade to these errata sharutils packages which
  contain a version of uudecode that has been patched to check for an
  existing pipe or symlink output file.




Solution : http://rhn.redhat.com/errata/RHSA-2003-180.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sharutils packages";
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
if ( rpm_check( reference:"sharutils-4.2.1-8.7.x", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"sharutils-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0178", value:TRUE);
}

set_kb_item(name:"RHSA-2003-180", value:TRUE);
