# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200402-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14448);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200402-04");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200402-04
(Gallery 1.4.1 and below remote exploit vulnerability)


    Starting in the 1.3.1 release, Gallery includes code to simulate the behaviour
    of the PHP \'register_globals\' variable in environments where that setting
    is disabled.  It is simulated by extracting the values of the various
    $HTTP_ global variables into the global namespace.
  
Impact

    A crafted URL such as
    http://example.com/gallery/init.php?HTTP_POST_VARS=xxx  causes the
    \'register_globals\' simulation code to overwrite the $HTTP_POST_VARS which,
    when it is extracted, will deliver the given payload. If the
    payload compromises $GALLERY_BASEDIR then the malicious user can perform a
    PHP injection exploit and gain remote access to the webserver with PHP
    user UID access rights.
  
Workaround

    The workaround for the vulnerability is to replace init.php and
    setup/init.php with the files in the following ZIP file:
    http://prdownloads.sourceforge.net/gallery/patch_1.4.1-to-1.4.1-pl1.zip?download
  

Solution: 
    All users are encouraged to upgrade their gallery installation:
    # emerge sync
    # emerge -p ">=app-misc/gallery-1.4.1_p1"
    # emerge ">=app-misc/gallery-1.4.1_p1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200402-04] Gallery 1.4.1 and below remote exploit vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gallery 1.4.1 and below remote exploit vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-misc/gallery", unaffected: make_list("ge 1.4.1_p1"), vulnerable: make_list("lt 1.4.1_p1")
)) { security_warning(0); exit(0); }
