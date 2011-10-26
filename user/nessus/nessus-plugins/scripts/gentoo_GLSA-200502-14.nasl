# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16451);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200502-14");
 script_cve_id("CVE-2005-0088");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-14
(mod_python: Publisher Handler vulnerability)


    Graham Dumpleton discovered a vulnerability in mod_python\'s
    Publisher Handler.
  
Impact

    By requesting a specially crafted URL for a published module page,
    an attacker could obtain information about restricted variables.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0088


Solution: 
    All mod_python users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-python/mod_python-3.1.3-r1"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-14] mod_python: Publisher Handler vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'mod_python: Publisher Handler vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-python/mod_python", unaffected: make_list("ge 3.1.3-r1"), vulnerable: make_list("lt 3.1.3-r1")
)) { security_warning(0); exit(0); }
