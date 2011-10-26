# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21707);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-14");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-14
(GDM: Privilege escalation)


    GDM allows a normal user to access the configuration manager.
  
Impact

    When the "face browser" in GDM is enabled, a normal user can use the
    "configure login manager" with his/her own password instead of the root
    password, and thus gain additional privileges.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://bugzilla.gnome.org/show_bug.cgi?id=343476
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2006-2452


Solution: 
    All GDM users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=gnome-base/gdm-2.8.0.8"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-14] GDM: Privilege escalation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GDM: Privilege escalation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "gnome-base/gdm", unaffected: make_list("ge 2.8.0.8"), vulnerable: make_list("lt 2.8.0.8")
)) { security_hole(0); exit(0); }
