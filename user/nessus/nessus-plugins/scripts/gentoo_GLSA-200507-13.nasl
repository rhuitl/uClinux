# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19200);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200507-13");
 script_cve_id("CVE-2005-2069");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-13
(pam_ldap and nss_ldap: Plain text authentication leak)


    Rob Holland of the Gentoo Security Audit Team discovered that
    pam_ldap and nss_ldap fail to use TLS for referred connections if they
    are referred to a master after connecting to a slave, regardless of the
    "ssl start_tls" ldap.conf setting.
  
Impact

    An attacker could sniff passwords or other sensitive information
    as the communication is not encrypted.
  
Workaround

    pam_ldap and nss_ldap can be set to force the use of SSL instead
    of TLS.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2069


Solution: 
    All pam_ldap users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-auth/pam_ldap-178-r1"
    All nss_ldap users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose sys-auth/nss_ldap
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-13] pam_ldap and nss_ldap: Plain text authentication leak");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'pam_ldap and nss_ldap: Plain text authentication leak');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-auth/pam_ldap", unaffected: make_list("ge 178-r1"), vulnerable: make_list("lt 178-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-auth/nss_ldap", unaffected: make_list("ge 239-r1", "rge 226-r1"), vulnerable: make_list("lt 239-r1")
)) { security_warning(0); exit(0); }
