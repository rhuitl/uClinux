# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200609-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22457);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200609-13");
 script_cve_id("CVE-2006-4334", "CVE-2006-4335", "CVE-2006-4336", "CVE-2006-4337", "CVE-2006-4338");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200609-13
(gzip: Multiple vulnerabilities)


    Tavis Ormandy of the Google Security Team has reported multiple
    vulnerabilities in gzip. A stack buffer modification vulnerability was
    discovered in the LZH decompression code, where a pathological data
    stream may result in the modification of stack data such as frame
    pointer, return address or saved registers. A static buffer underflow
    was discovered in the pack decompression support, allowing a specially
    crafted pack archive to underflow a .bss buffer. A static buffer
    overflow was uncovered in the LZH decompression code, allowing a data
    stream consisting of pathological huffman codes to overflow a .bss
    buffer. Multiple infinite loops were also uncovered in the LZH
    decompression code.
  
Impact

    A remote attacker may create a specially crafted gzip archive, which
    when decompressed by a user or automated system exectues arbitrary code
    with the privileges of the user id invoking gzip. The infinite loops
    may be abused by an attacker to disrupt any automated systems invoking
    gzip to handle data decompression.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4334
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4335
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4336
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4337
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4338


Solution: 
    All gzip users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/gzip-1.3.5-r9"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200609-13] gzip: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'gzip: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-arch/gzip", unaffected: make_list("ge 1.3.5-r9"), vulnerable: make_list("lt 1.3.5-r9")
)) { security_warning(0); exit(0); }
