# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19669);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200509-04");
 script_cve_id("CVE-2005-2654");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200509-04
(phpLDAPadmin: Authentication bypass)


    Alexander Gerasiov discovered a flaw in login.php preventing the
    application from validating whether anonymous bind has been disabled in
    the target LDAP server configuration.
  
Impact

    Anonymous users can access the LDAP server, even if the
    "disable_anon_bind" parameter was explicitly set to avoid this.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2654
    http://secunia.com/advisories/16611/


Solution: 
    All phpLDAPadmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-nds/phpldapadmin-0.9.7_alpha6"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200509-04] phpLDAPadmin: Authentication bypass");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpLDAPadmin: Authentication bypass');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-nds/phpldapadmin", unaffected: make_list("ge 0.9.7_alpha6"), vulnerable: make_list("lt 0.9.7_alpha6")
)) { security_warning(0); exit(0); }
