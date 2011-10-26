# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-22.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17127);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200502-22");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-22
(wpa_supplicant: Buffer overflow vulnerability)


    wpa_supplicant contains a possible buffer overflow due to the
    lacking validation of received EAPOL-Key frames.
  
Impact

    An attacker could cause the crash of wpa_supplicant using a
    specially crafted packet.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://lists.shmoo.com/pipermail/hostap/2005-February/009465.html


Solution: 
    All wpa_supplicant users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-wireless/wpa_supplicant-0.2.7"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-22] wpa_supplicant: Buffer overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'wpa_supplicant: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-wireless/wpa_supplicant", unaffected: make_list("ge 0.2.7"), vulnerable: make_list("lt 0.2.7")
)) { security_warning(0); exit(0); }
