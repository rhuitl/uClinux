# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19577);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200509-02");
 script_cve_id("CVE-2005-2491");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200509-02
(Gnumeric: Heap overflow in the included PCRE library)


    Gnumeric contains a private copy of libpcre which is subject to an
    integer overflow leading to a heap overflow (see GLSA 200508-17).
  
Impact

    An attacker could potentially exploit this vulnerability by
    tricking a user into opening a specially crafted spreadsheet, which
    could lead to the execution of arbitrary code with the privileges of
    the user running Gnumeric.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2491
    http://www.gentoo.org/security/en/glsa/glsa-200508-17.xml


Solution: 
    All Gnumeric users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/gnumeric-1.4.3-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200509-02] Gnumeric: Heap overflow in the included PCRE library");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gnumeric: Heap overflow in the included PCRE library');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-office/gnumeric", unaffected: make_list("ge 1.4.3-r2"), vulnerable: make_list("lt 1.4.3-r2")
)) { security_warning(0); exit(0); }
