# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14466);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200404-01");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200404-01
(Insecure sandbox temporary lockfile vulnerabilities in Portage)


    A flaw in Portage\'s sandbox wrapper has been found where the temporary
    lockfiles are subject to a hard-link attack which allows linkable files to
    be overwritten to an empty file. This can be used to damage critical files
    on a system causing a Denial of Service, or alternatively this attack may
    be used to cause other security risks; for example firewall configuration
    data could be overwritten without notice.
    The vulnerable sandbox functions have been patched to test for these new
    conditions: namely; for the existance of a hard-link which would be removed
    before the sandbox process would continue, for the existance of a
    world-writable lockfile in which case the sandbox would also remove it, and
    also for any mismatches in the UID ( anything but root ) and the GID (
    anything but the group of the sandbox process ).
    If the vulnerable files cannot be removed by the sandbox, then the sandbox
    would exit with a fatal error warning the adminstrator of the issue. The
    patched functions also fix any other sandbox I/O operations which do not
    explicitly include the mentioned lockfile.
  
Impact

    Any user with write access to the /tmp directory can hard-link a file to
    /tmp/sandboxpids.tmp - this file would eventually be replaced with an empty
    one; effectively wiping out the file it was linked to as well with no prior
    warning. This could be used to potentially disable a vital component of the
    system and cause a path for other possible exploits.
    This vulnerability only affects systems that have /tmp on the root
    partition: since symbolic link attacks are filtered, /tmp has to be on the
    same partition for an attack to take place.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  

Solution: 
    Users should upgrade to Portage 2.0.50-r3 or later:
    # emerge sync
    # emerge -pv ">=sys-apps/portage-2.0.50-r3"
    # emerge ">=sys-apps/portage-2.0.50-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200404-01] Insecure sandbox temporary lockfile vulnerabilities in Portage");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Insecure sandbox temporary lockfile vulnerabilities in Portage');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-apps/portage", unaffected: make_list("ge 2.0.50-r3"), vulnerable: make_list("lt 2.0.50-r3")
)) { security_warning(0); exit(0); }
