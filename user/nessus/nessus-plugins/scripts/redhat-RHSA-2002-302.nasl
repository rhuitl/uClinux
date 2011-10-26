#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12344);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1377");

 name["english"] = "RHSA-2002-302: vim";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated VIM packages are available for Red Hat Linux Advanced Server.
  These updates resolve a security issue when opening a specially-crafted
  text
  file.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  VIM (VIsual editor iMproved) is a version of the vi editor.

  VIM allows a user to set the modeline differently for each edited text
  file by placing special comments in the files. Georgi Guninski found that
  these comments can be carefully crafted in order to call external programs.
  This could allow an attacker to create a text file such that when it is
  opened arbitrary commands are executed.

  Users of VIM are advised to upgrade to these errata packages which have
  been patched to disable the usage of dangerous funtions in modelines.




Solution : http://rhn.redhat.com/errata/RHSA-2002-302.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the vim packages";
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
if ( rpm_check( reference:"vim-common-6.0-7.15", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-enhanced-6.0-7.15", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-minimal-6.0-7.15", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-X11-6.0-7.15", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"vim-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1377", value:TRUE);
}

set_kb_item(name:"RHSA-2002-302", value:TRUE);
