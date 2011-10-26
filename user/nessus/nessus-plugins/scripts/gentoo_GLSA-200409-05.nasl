# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14652);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200409-05");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-05
(Gallery: Arbitrary command execution)


    The upload handling code in Gallery places uploaded files in a temporary
    directory. After 30 seconds, these files are deleted if they are not valid
    images. However, since the file exists for 30 seconds, a carefully crafted
    script could be initiated by the remote attacker during this 30 second
    timeout. Note that the temporary directory has to be located inside the
    webroot and an attacker needs to have upload rights either as an
    authenticated user or via "EVERYBODY".
  
Impact

    An attacker could run arbitrary code as the user running PHP.
  
Workaround

    There are several workarounds to this vulnerability:
    Make sure that your temporary directory is not contained in the
    webroot; by default it is located outside the webroot.
    Disable upload rights to all albums for "EVERYBODY"; upload
    is disabled by default.
    Disable debug and dev mode; these settings are disabled by
    default.
    Disable allow_url_fopen in php.ini.
  
References:
    http://archives.neohapsis.com/archives/fulldisclosure/2004-08/0757.html
    http://gallery.menalto.com/modules.php?op=modload&name=News&file=article&sid=134&mode=thread&order=0&thold=0


Solution: 
    All Gallery users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=www-apps/gallery-1.4.4_p2"
    # emerge ">=www-apps/gallery-1.4.4_p2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-05] Gallery: Arbitrary command execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gallery: Arbitrary command execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/gallery", unaffected: make_list("ge 1.4.4_p2"), vulnerable: make_list("lt 1.4.4_p2")
)) { security_warning(0); exit(0); }
