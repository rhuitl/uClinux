# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20154);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200511-04");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200511-04
(ClamAV: Multiple vulnerabilities)


    ClamAV has multiple security flaws: a boundary check was performed
    incorrectly in petite.c, a buffer size calculation in unfsg_133 was
    incorrect in fsg.c, a possible infinite loop was fixed in tnef.c and a
    possible infinite loop in cabd_find was fixed in cabd.c . In addition
    to this, Marcin Owsiany reported that a corrupted DOC file causes a
    segmentation fault in ClamAV.
  
Impact

    By sending a malicious attachment to a mail server that is hooked
    with ClamAV, a remote attacker could cause a Denial of Service or the
    execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3239
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3303
    http://sourceforge.net/project/shownotes.php?release_id=368319
    http://www.zerodayinitiative.com/advisories/ZDI-05-002.html


Solution: 
    All ClamAV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/clamav-0.87.1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200511-04] ClamAV: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.87.1"), vulnerable: make_list("lt 0.87.1")
)) { security_hole(0); exit(0); }
