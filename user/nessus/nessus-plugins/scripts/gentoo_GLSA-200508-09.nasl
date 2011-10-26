# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19442);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200508-09");
 script_cve_id("CVE-2005-2547");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200508-09
(bluez-utils: Bluetooth device name validation vulnerability)


    The name of a Bluetooth device is improperly validated by the hcid
    utility when a remote device attempts to pair itself with a computer.
  
Impact

    An attacker could create a malicious device name on a Bluetooth
    device resulting in arbitrary commands being executed as root upon
    attempting to pair the device with the computer.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2547
    http://cvs.sourceforge.net/viewcvs.py/bluez/utils/ChangeLog?rev=1.28&view=markup


Solution: 
    All bluez-utils users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-wireless/bluez-utils-2.19"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200508-09] bluez-utils: Bluetooth device name validation vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'bluez-utils: Bluetooth device name validation vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-wireless/bluez-utils", unaffected: make_list("ge 2.19"), vulnerable: make_list("lt 2.19")
)) { security_hole(0); exit(0); }
