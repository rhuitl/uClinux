# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20327);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200512-07");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200512-07
(OpenLDAP, Gauche: RUNPATH issues)


    Gentoo packaging for OpenLDAP and Gauche may introduce insecure
    paths into the list of directories that are searched for libraries at
    runtime.
  
Impact

    A local attacker, who is a member of the "portage" group, could
    create a malicious shared object in the Portage temporary build
    directory that would be loaded at runtime by a dependent binary,
    potentially resulting in privilege escalation.
  
Workaround

    Only grant "portage" group rights to trusted users.
  

Solution: 
    All OpenLDAP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose net-nds/openldap
    All Gauche users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/gauche-0.8.6-r1"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200512-07] OpenLDAP, Gauche: RUNPATH issues");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenLDAP, Gauche: RUNPATH issues');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-lang/gauche", unaffected: make_list("ge 0.8.6-r1"), vulnerable: make_list("lt 0.8.6-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-nds/openldap", unaffected: make_list("ge 2.2.28-r3", "rge 2.1.30-r6"), vulnerable: make_list("lt 2.2.28-r3")
)) { security_warning(0); exit(0); }
