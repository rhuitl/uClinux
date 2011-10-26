#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12359);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1395");

 name["english"] = "RHSA-2003-038: im";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Internet Message packages are available that fix the insecure
  handling of temporary files.

  [Updated 9 April 2003]
  Added packages for Red Hat Linux Advanced Workstation, Red Hat Enterprise
  Linux ES, and Red Hat Enterprise Linux WS.

  Internet Message (IM) consists of a set of user interface commands and
  backend Perl5 libraries to integrate email and the NetNews user interface.
  These commands are designed to be used from both the Mew mail reader for
  Emacs and the command line.

  A vulnerability has been discovered by Tatsuya Kinoshita in the way two IM
  utilities create temporary files. By anticipating the names used to
  create files and directories stored in the /tmp directory, it may be
  possible for a local attacker to corrupt or modify data as another user.

  Users of IM are advised to install these packages which contain a
  backported patch to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2003-038.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the im packages";
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
if ( rpm_check( reference:"im-140-3.21AS.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"im-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1395", value:TRUE);
}

set_kb_item(name:"RHSA-2003-038", value:TRUE);
