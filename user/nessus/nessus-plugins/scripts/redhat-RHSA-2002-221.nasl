#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12328);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1247", "CVE-2002-1306", "CVE-2002-0970", "CVE-2002-1151");

 name["english"] = "RHSA-2002-221: arts";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  A number of vulnerabilities have been found that affect various versions of
  KDE. This errata provides updates for these issues.

  KDE is a graphical desktop environment for workstations. A number
  of vulnerabilities have been found in various versions of KDE.

  The SSL capability for Konqueror in KDE 3.0.2 and earlier does not
  verify the Basic Constraints for an intermediate CA-signed certificate,
  which allows remote attackers to spoof the certificates of trusted
  sites via a man-in-the-middle attack. The Common Vulnerabilities and
  Exposures project has assigned the name CVE-2002-0970 to this issue.

  The cross-site scripting protection for Konqueror in KDE 2.2.2 and 3.0
  through 3.0.3 does not properly initialize the domains on sub-frames
  and sub-iframes, which can allow remote attackers to execute scripts
  and steal cookies from subframes that are in other domains. (CVE-2002-1151)

  Multiple buffer overflows exist in the KDE LAN browsing implementation;
  the reslisa daemon contains a buffer overflow vulnerability which could
  be exploited if the reslisa binary is SUID root. Additionally, the lisa
  daemon contains a vulnerability which potentially enables any local
  user, as well any any remote attacker on the LAN who is able to gain
  control of the LISa port (7741 by default), to obtain root privileges.
  In Red Hat Linux reslisa is not SUID root and lisa services are not
  automatically started. (CVE-2002-1247, CVE-2002-1306)

  Red Hat Linux Advanced Server 2.1 provides KDE version 2.2.2 and is
  therefore vulnerable to these issues. This errata provides new kdelibs and
  kdenetworks packages which contain patches to correct these issues.

  Please note that there is are two additional vulnerabilities that affect
  KDE 2.x which are not fixed by this errata. A vulnerability in the rlogin
  KIO subsystem (rlogin.protocol) of KDE 2.x 2.1 and later, and KDE 3.x 3.0.4
  and earlier, allows local and remote attackers to execute arbitrary code
  via a carefully crafted URL. (CVE-2002-1281). A similar vulnerability
  affects the telnet KIO subsystem (telnet.protocol) of KDE 2.x 2.1 and
  later. (CVE-2002-1282)

  At this time, Red Hat recommends disabling both the rlogin and telnet
  KIO protocols as a workaround. To disable both protocols, execute
  these commands while logged in as root:

  rm /usr/share/services/rlogin.protocol
  rm /usr/share/services/telnet.protocol




Solution : http://rhn.redhat.com/errata/RHSA-2002-221.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the arts packages";
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
if ( rpm_check( reference:"arts-2.2.2-3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-2.2.2-3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-2.2.2-3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-2.2.2-3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-devel-2.2.2-3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-2.2.2-2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-ppp-2.2.2-2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"arts-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1247", value:TRUE);
 set_kb_item(name:"CVE-2002-1306", value:TRUE);
 set_kb_item(name:"CVE-2002-0970", value:TRUE);
 set_kb_item(name:"CVE-2002-1151", value:TRUE);
}

set_kb_item(name:"RHSA-2002-221", value:TRUE);
