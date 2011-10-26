# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18448);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200506-06");
 script_cve_id("CVE-2005-0064");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200506-06
(libextractor: Multiple overflow vulnerabilities)


    Xpdf is vulnerable to multiple overflows, as described in GLSA
    200501-28. Also, integer overflows were discovered in Real and PNG
    extractors.
  
Impact

    An attacker could design malicious PDF, PNG or Real files which,
    when processed by an application making use of libextractor, would
    result in the execution of arbitrary code with the rights of the user
    running the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0064
    http://www.gentoo.org/security/en/glsa/glsa-200501-28.xml
    http://gnunet.org/libextractor/


Solution: 
    All libextractor users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libextractor-0.5.0"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200506-06] libextractor: Multiple overflow vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libextractor: Multiple overflow vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/libextractor", unaffected: make_list("ge 0.5.0"), vulnerable: make_list("lt 0.5.0")
)) { security_warning(0); exit(0); }
