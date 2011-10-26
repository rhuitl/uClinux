# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200401-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14443);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200401-03");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200401-03
(Apache mod_python Denial of Service vulnerability)


    The Apache Foundation has reported that mod_python may be prone to
    Denial of Service attacks when handling a malformed
    query. Mod_python 2.7.9 was released to fix the vulnerability,
    however, because the vulnerability has not been fully fixed,
    version 2.7.10 has been released.
    Users of mod_python 3.0.4 are not affected by this vulnerability.
  
Impact

    Although there are no known public exploits known for this
    exploit, users are recommended to upgrade mod_python to ensure the
    security of their infrastructure.
  
Workaround

    Mod_python 2.7.10 has been released to solve this issue; there is
    no immediate workaround.
  
References:
    http://www.modpython.org/pipermail/mod_python/2004-January/014879.html


Solution: 
    All users using mod_python 2.7.9 or below are recommended to
    update their mod_python installation:
    $> emerge sync
    $> emerge -pv ">=dev-python/mod_python-2.7.10"
    $> emerge ">=dev-python/mod_python-2.7.10"
    $> /etc/init.d/apache restart
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200401-03] Apache mod_python Denial of Service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache mod_python Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-python/mod_python", unaffected: make_list("ge 2.7.10"), vulnerable: make_list("lt 2.7.10")
)) { security_warning(0); exit(0); }
