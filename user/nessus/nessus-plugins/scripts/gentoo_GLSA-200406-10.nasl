# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14521);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200406-10");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200406-10
(Gallery: Privilege escalation vulnerability)


    There is a vulnerability in the Gallery photo album software which may
    allow an attacker to gain administrator privileges within Gallery. A
    Gallery administrator has full access to all albums and photos on the
    server, thus attackers may add or delete photos at will.
  
Impact

    Attackers may gain full access to all Gallery albums. There is no risk to
    the webserver itself, or the server on which it runs.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
References:
    http://gallery.menalto.com/modules.php?op=modload&name=News&file=article&sid=123&mode=thread&order=0&thold=0


Solution: 
    All users should upgrade to the latest available version of Gallery.
    # emerge sync
    # emerge -pv ">=app-misc/gallery-1.4.3_p2"
    # emerge ">=app-misc/gallery-1.4.3_p2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200406-10] Gallery: Privilege escalation vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gallery: Privilege escalation vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-misc/gallery", unaffected: make_list("ge 1.4.3_p2"), vulnerable: make_list("le 1.4.3_p1")
)) { security_warning(0); exit(0); }
