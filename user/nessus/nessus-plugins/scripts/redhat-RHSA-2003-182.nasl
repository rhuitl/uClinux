#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12399);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0354");

 name["english"] = "RHSA-2003-182: ghostscript";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  A ghostscript package fixing a command execution vulnerability is now
  available.

  GNU Ghostscript is an interpreter for the PostScript language, and is often
  used when printing to printers that do not have their own built-in
  PostScript interpreter.

  A flaw has been discovered in the way Ghostscript validates some PostScript
  commands. This flaw allows an attacker to force commands to be executed by
  a print spooler by submitting a malicious print job. Note that using the
  -dSAFER option is not sufficient to prevent command execution.

  Users of Ghostscript are advised to upgrade to these updated packages,
  which are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-182.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ghostscript packages";
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
if ( rpm_check( reference:"ghostscript-6.51-16.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ghostscript-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0354", value:TRUE);
}

set_kb_item(name:"RHSA-2003-182", value:TRUE);
