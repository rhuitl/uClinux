#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12371);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0077", "CVE-2003-0079");

 name["english"] = "RHSA-2003-071: hanterm";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Hangul Terminal packages fix two security issues.

  Hangul Terminal is a terminal emulator for the X Window System, based on
  Xterm.

  Hangul Terminal provides an escape sequence for reporting the current
  window title, which essentially takes the current title and places it
  directly on the command line. An attacker can craft an escape sequence
  that sets the window title of a victim using Hangul Terminal to an
  arbitrary command and then report it to the command line. Since it is not
  possible to embed a carriage return into the window title the attacker
  would then have to convince the victim to press Enter for it to process the
  title as a command, although the attacker could craft other escape
  sequences that might convince the victim to do so.

  It is possible to lock up Hangul Terminal before version 2.0.5 by sending
  an invalid DEC UDK escape sequence.

  Users are advised to upgrade to these erratum packages, which contain
  Hangul Terminal version 2.0.5 which is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2003-071.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the hanterm packages";
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
if ( rpm_check( reference:"hanterm-xf-2.0.5-5.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"hanterm-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0077", value:TRUE);
 set_kb_item(name:"CVE-2003-0079", value:TRUE);
}

set_kb_item(name:"RHSA-2003-071", value:TRUE);
