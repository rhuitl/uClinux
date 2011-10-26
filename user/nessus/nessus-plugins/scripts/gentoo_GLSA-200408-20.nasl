# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-20.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14576);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200408-20");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-20
(Qt: Image loader overflows)


    There are several unspecified bugs in the QImage class which may cause
    crashes or allow execution of arbitrary code as the user running the Qt
    application. These bugs affect the PNG, XPM, BMP, GIF and JPEG image types.
  
Impact

    An attacker may exploit these bugs by causing a user to open a
    carefully-constructed image file in any one of these formats. This may be
    accomplished through e-mail attachments (if the user uses KMail), or by
    simply placing a malformed image on a website and then convicing the user
    to load the site in a Qt-based browser (such as Konqueror).
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of Qt.
  
References:
    http://www.mandrakesoft.com/security/advisories?name=MDKSA-2004:085
    http://www.trolltech.com/developer/changes/changes-3.3.3.html


Solution: 
    All Qt users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=x11-libs/qt-3.3.3"
    # emerge ">=x11-libs/qt-3.3.3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-20] Qt: Image loader overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Qt: Image loader overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "x11-libs/qt", unaffected: make_list("ge 3.3.3"), vulnerable: make_list("le 3.3.2")
)) { security_warning(0); exit(0); }
