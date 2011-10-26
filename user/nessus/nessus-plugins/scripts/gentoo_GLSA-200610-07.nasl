# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200610-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22893);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200610-07");
 script_cve_id("CVE-2006-4980");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200610-07
(Python: Buffer Overflow)


    Benjamin C. Wiley Sittler discovered a buffer overflow in Python\'s
    "repr()" function when handling UTF-32/UCS-4 encoded strings.
  
Impact

    If a Python application processes attacker-supplied data with the
    "repr()" function, this could potentially lead to the execution of
    arbitrary code with the privileges of the affected application or a
    Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4980


Solution: 
    All Python users should update to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/python-2.4.3-r4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200610-07] Python: Buffer Overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Python: Buffer Overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-lang/python", unaffected: make_list("ge 2.4.3-r4", "rge 2.3.5-r3"), vulnerable: make_list("lt 2.4.3-r4")
)) { security_warning(0); exit(0); }
