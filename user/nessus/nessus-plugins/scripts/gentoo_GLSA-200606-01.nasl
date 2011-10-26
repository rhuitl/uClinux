# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21663);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-01");
 script_cve_id("CVE-2006-1834");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-01
(Opera: Buffer overflow)


    SEC Consult has discovered a buffer overflow in the code
    processing style sheet attributes. It is caused by an integer
    signedness error in a length check followed by a call to a string
    function. It seems to be hard to exploit this buffer overflow to
    execute arbitrary code because of the very large amount memory that has
    to be copied.
  
Impact

    A remote attacker can entice a user to visit a web page containing
    a specially crafted style sheet attribute that will crash the user\'s
    browser and maybe lead to the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1834


Solution: 
    All Opera users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/opera-8.54"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-01] Opera: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Opera: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-client/opera", unaffected: make_list("ge 8.54"), vulnerable: make_list("lt 8.54")
)) { security_warning(0); exit(0); }
