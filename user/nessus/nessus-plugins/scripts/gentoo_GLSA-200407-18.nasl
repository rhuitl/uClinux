# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14551);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200407-18");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200407-18
(mod_ssl: Format string vulnerability)


    A bug in ssl_engine_ext.c makes mod_ssl vulnerable to a ssl_log() related
    format string vulnerability in the mod_proxy hook functions.
  
Impact

    Given the right server configuration, an attacker could execute code as the
    user running Apache, usually "apache".
  
Workaround

    A server should not be vulnerable if it is not using both mod_ssl and
    mod_proxy. Otherwise there is no workaround other than to disable mod_ssl.
  
References:
    http://marc.theaimsgroup.com/?l=apache-modssl&m=109001100906749&w=2


Solution: 
    All mod_ssl users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-www/mod_ssl-2.8.19"
    # emerge ">=net-www/mod_ssl-2.8.19"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200407-18] mod_ssl: Format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'mod_ssl: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/mod_ssl", unaffected: make_list("ge 2.8.19"), vulnerable: make_list("le 2.8.18")
)) { security_warning(0); exit(0); }
