#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21638);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2453", "CVE-2006-2480");

 name["english"] = "RHSA-2006-0541: dia";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Dia packages that fix several buffer overflow bugs are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Dia drawing program is designed to draw various types of diagrams.

  Several format string flaws were found in the way dia displays certain
  messages. If an attacker is able to trick a Dia user into opening a
  carefully crafted file, it may be possible to execute arbitrary code as the
  user running Dia. (CVE-2006-2453, CVE-2006-2480)

  Users of Dia should update to these erratum packages, which contain
  backported patches and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0541.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the dia packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"dia-0.94-5.7.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"dia-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-2453", value:TRUE);
 set_kb_item(name:"CVE-2006-2480", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0541", value:TRUE);
