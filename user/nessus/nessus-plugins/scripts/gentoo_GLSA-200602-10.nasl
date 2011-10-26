# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200602-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20938);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200602-10");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200602-10
(GnuPG: Incorrect signature verification)


    Tavis Ormandy of the Gentoo Linux Security Auditing Team
    discovered that automated systems relying on the return code of GnuPG
    or gpgv to authenticate digital signatures may be misled by malformed
    signatures. GnuPG documentation states that a return code of zero (0)
    indicates success, however gpg and gpgv may also return zero if no
    signature data was found in a detached signature file.
  
Impact

    An attacker may be able to bypass authentication in automated
    systems relying on the return code of gpg or gpgv to authenticate
    digital signatures.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://lists.gnupg.org/pipermail/gnupg-announce/2006q1/000211.html
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0455


Solution: 
    All GnuPG users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/gnupg-1.4.2.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200602-10] GnuPG: Incorrect signature verification");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GnuPG: Incorrect signature verification');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-crypt/gnupg", unaffected: make_list("ge 1.4.2.1"), vulnerable: make_list("lt 1.4.2.1")
)) { security_warning(0); exit(0); }
