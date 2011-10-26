# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15649);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200411-15");
 script_cve_id("CVE-2004-0969", "CVE-2004-0975");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-15
(OpenSSL, Groff: Insecure tempfile handling)


    groffer and the der_chop script create temporary files in world-writeable directories with predictable names.
  
Impact

    A local attacker could create symbolic links in the temporary files directory, pointing to a valid file somewhere on the filesystem. When groffer or der_chop is executed, this would result in the file being overwritten with the rights of the user running the utility, which could be the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0969
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0975


Solution: 
    All Groff users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-apps/groff-1.19.1-r2"
    All OpenSSL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/openssl-0.9.7d-r2"
    Note: /etc/ssl/misc/der_chop is protected by Portage as a configuration file. Don\'t forget to use etc-update and overwrite the old version with the new one.
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-15] OpenSSL, Groff: Insecure tempfile handling");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenSSL, Groff: Insecure tempfile handling');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-apps/groff", unaffected: make_list("ge 1.19.1-r2"), vulnerable: make_list("lt 1.19.1-r2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-libs/openssl", unaffected: make_list("ge 0.9.7d-r2"), vulnerable: make_list("lt 0.9.7d-r2")
)) { security_warning(0); exit(0); }
