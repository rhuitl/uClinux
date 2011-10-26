# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14463);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200403-12");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200403-12
(OpenLDAP DoS Vulnerability)


    A password extended operation (password EXOP) which fails will cause the
    slapd server to free() an uninitialized pointer, possibly resulting in a
    segfault. This only affects servers using the back-ldbm backend.
    Such a crash is not guaranteed with every failed operation, however, it is
    possible.
  
Impact

    An attacker (or indeed, a normal user) may crash the OpenLDAP server,
    creating a Denial of Service condition.
  
Workaround

    A workaround is not currently known for this issue.  All users are
    advised to upgrade to the latest version of OpenLDAP.
  
References:
    http://www.openldap.org/its/index.cgi?findid=2390


Solution: 
    OpenLDAP users should upgrade to version 2.1.17 or later:
    # emerge sync
    # emerge -pv ">=net-nds/openldap-2.1.17"
    # emerge ">=net-nds/openldap-2.1.17"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200403-12] OpenLDAP DoS Vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenLDAP DoS Vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-nds/openldap", unaffected: make_list("ge 2.1.17"), vulnerable: make_list("le 2.1.16")
)) { security_warning(0); exit(0); }
