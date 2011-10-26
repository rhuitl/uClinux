# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18230);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200505-04");
 script_cve_id("CVE-2005-1431");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200505-04
(GnuTLS: Denial of Service vulnerability)


    A vulnerability has been discovered in the record packet parsing
    in the GnuTLS library. Additionally, a flaw was also found in the RSA
    key export functionality.
  
Impact

    A remote attacker could exploit this vulnerability and cause a
    Denial of Service to any application that utilizes the GnuTLS library.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://lists.gnupg.org/pipermail/gnutls-dev/2005-April/000858.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1431


Solution: 
    All GnuTLS users should remove the existing installation and
    upgrade to the latest version:
    # emerge --sync
    # emerge --unmerge gnutls
    # emerge --ask --oneshot --verbose net-libs/gnutls
    Due to small API changes with the previous version, please do
    the following to ensure your applications are using the latest GnuTLS
    that you just emerged.
    # revdep-rebuild --soname-regexp libgnutls.so.1[0-1]
    Previously exported RSA keys can be fixed by executing the
    following command on the key files:
    # certtool -k infile outfile
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200505-04] GnuTLS: Denial of Service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GnuTLS: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-libs/gnutls", unaffected: make_list("ge 1.2.3", "rge 1.0.25"), vulnerable: make_list("lt 1.2.3")
)) { security_warning(0); exit(0); }
