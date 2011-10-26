# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-24.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21750);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-24");
 script_cve_id("CVE-2006-2197");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-24
(wv2: Integer overflow)


    A boundary checking error was found in wv2, which could lead to an
    integer overflow.
  
Impact

    An attacker could execute arbitrary code with the rights of the user
    running the program that uses the library via a maliciously crafted
    Microsoft Word document.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2197


Solution: 
    All wv2 users should update to the latest stable version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/wv2-0.2.3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-24] wv2: Integer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'wv2: Integer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/wv2", unaffected: make_list("ge 0.2.3"), vulnerable: make_list("lt 0.2.3")
)) { security_warning(0); exit(0); }
