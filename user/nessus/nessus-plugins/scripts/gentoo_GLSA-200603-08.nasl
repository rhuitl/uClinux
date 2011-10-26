# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21046);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-08");
 script_cve_id("CVE-2006-0049");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-08
(GnuPG: Incorrect signature verification)


    OpenPGP is the standard that defines the format of digital
    signatures supported by GnuPG. OpenPGP signatures consist of multiple
    sections, in a strictly defined order. Tavis Ormandy of the Gentoo
    Linux Security Audit Team discovered that certain illegal signature
    formats could allow signed data to be modified without detection. GnuPG
    has previously attempted to be lenient when processing malformed or
    legacy signature formats, but this has now been found to be insecure.
  
Impact

    A remote attacker may be able to construct or modify a
    digitally-signed message, potentially allowing them to bypass
    authentication systems, or impersonate another user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0049
    http://lists.gnupg.org/pipermail/gnupg-announce/2006q1/000216.html


Solution: 
    All GnuPG users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/gnupg-1.4.2.2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-08] GnuPG: Incorrect signature verification");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GnuPG: Incorrect signature verification');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-crypt/gnupg", unaffected: make_list("ge 1.4.2.2"), vulnerable: make_list("lt 1.4.2.2")
)) { security_warning(0); exit(0); }
