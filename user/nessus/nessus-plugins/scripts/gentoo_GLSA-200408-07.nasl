# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14563);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200408-07");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-07
(Horde-IMP: Input validation vulnerability for Internet Explorer users)


    Horde-IMP fails to properly sanitize email messages that contain malicious
    HTML or script code so that it is not safe for users of Internet Explorer
    when using the inline MIME viewer for HTML messages.
  
Impact

    By enticing a user to read a specially crafted e-mail, an attacker can
    execute arbitrary scripts running in the context of the victim\'s browser.
    This could lead to a compromise of the user\'s webmail account, cookie
    theft, etc.
  
Workaround

    Do not use Internet Explorer to access Horde-IMP.
  
References:
    http://cvs.horde.org/diff.php/imp/docs/CHANGES?r1=1.389.2.106&r2=1.389.2.109&ty=h
    http://secunia.com/advisories/12202/


Solution: 
    All Horde-IMP users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=horde-imp-3.2.5"
    # emerge ">=horde-imp-3.2.5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-07] Horde-IMP: Input validation vulnerability for Internet Explorer users");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Horde-IMP: Input validation vulnerability for Internet Explorer users');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/horde-imp", unaffected: make_list("ge 3.2.5"), vulnerable: make_list("le 3.2.4")
)) { security_warning(0); exit(0); }
