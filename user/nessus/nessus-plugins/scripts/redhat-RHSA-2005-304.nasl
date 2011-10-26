#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17644);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0706");

 name["english"] = "RHSA-2005-304: grip";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  A new grip package is available that fixes a remote buffer overflow.

  This update has been rated as having moderate security impact by the Red
  Hat
  Security Response Team.

  Grip is a GTK+ based front-end for CD rippers (such as cdparanoia and
  cdda2wav) and Ogg Vorbis encoders.

  Dean Brettle discovered a buffer overflow bug in the way grip handles data
  returned by CDDB servers. It is possible that if a user connects to a
  malicious CDDB server, an attacker could execute arbitrary code on the
  victim\'s machine. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-0706 to this issue.

  Users of grip should upgrade to this updated package, which
  contains a backported patch, and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-304.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the grip packages";
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
if ( rpm_check( reference:"grip-2.96-1.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"grip-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0706", value:TRUE);
}

set_kb_item(name:"RHSA-2005-304", value:TRUE);
