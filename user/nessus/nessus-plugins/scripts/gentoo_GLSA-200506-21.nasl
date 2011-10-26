# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-21.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18548);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200506-21");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200506-21
(Trac: File upload vulnerability)


    Stefan Esser of the Hardened-PHP project discovered that Trac
    fails to validate the "id" parameter when uploading attachments to the
    wiki or the bug tracking system.
  
Impact

    A remote attacker could exploit the vulnerability to upload
    arbitrary files to a directory where the webserver has write access to,
    possibly leading to the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.hardened-php.net/advisory-012005.php


Solution: 
    All Trac users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/trac-0.8.4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200506-21] Trac: File upload vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Trac: File upload vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/trac", unaffected: make_list("ge 0.8.4"), vulnerable: make_list("lt 0.8.4")
)) { security_warning(0); exit(0); }
