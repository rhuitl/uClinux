# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-23.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18564);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200506-23");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200506-23
(Clam AntiVirus: Denial of Service vulnerability)


    Andrew Toller and Stefan Kanthak discovered that a flaw in
    libmspack\'s Quantum archive decompressor renders Clam AntiVirus
    vulnerable to a Denial of Service attack.
  
Impact

    A remote attacker could exploit this vulnerability to cause a
    Denial of Service by sending a specially crafted Quantum archive to the
    server.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://sourceforge.net/project/shownotes.php?release_id=337279


Solution: 
    All Clam AntiVirus users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/clamav-0.86.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200506-23] Clam AntiVirus: Denial of Service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Clam AntiVirus: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.86.1"), vulnerable: make_list("lt 0.86.1")
)) { security_warning(0); exit(0); }
