#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12365);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0022", "CVE-2003-0023", "CVE-2003-0066");

 name["english"] = "RHSA-2003-055: rxvt";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated rxvt packages are available which fix a number of vulnerabilities
  in the handling of escape sequences.

  [Updated 12 March 2003]
  Added packages for Red Hat Enterprise Linux ES and Red Hat Enterprise
  Linux WS

  Rxvt is a color VT102 terminal emulator for the X Window System. A number
  of issues have been found in the escape sequence handling of Rxvt.
  These could be potentially exploited if an attacker can cause carefully
  crafted escape sequences to be displayed on an rxvt terminal being used by
  their victim.

  One of the features which most terminal emulators support is the ability
  for the shell to set the title of the window using an escape sequence.
  Certain xterm variants, including rxvt, also provide an escape sequence for
  reporting the current window title. This essentially takes the current
  title and places it directly on the command line. Since it is not
  possible to embed a carriage return into the window title itself, the
  attacker would have to convince the victim to press the Enter key for the
  title to be processed as a command, although the attacker can perform a
  number of actions to increase the likelihood of this happening.

  A certain escape sequence when displayed in rxvt will create an arbitrary
  file.

  It is possible to add malicious items to the dynamic menus through an
  escape sequence.

  Users of Rxvt are advised to upgrade to these errata packages which contain
  a patch to disable the title reporting functionality and patches to correct
  the other issues.

  Red Hat would like to thank H D Moore for bringing these issues to our
  attention.




Solution : http://rhn.redhat.com/errata/RHSA-2003-055.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the rxvt packages";
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
if ( rpm_check( reference:"rxvt-2.7.8-4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"rxvt-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0022", value:TRUE);
 set_kb_item(name:"CVE-2003-0023", value:TRUE);
 set_kb_item(name:"CVE-2003-0066", value:TRUE);
}

set_kb_item(name:"RHSA-2003-055", value:TRUE);
