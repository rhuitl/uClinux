# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19199);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200507-12");
 script_cve_id("CVE-2005-2173", "CVE-2005-2174");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-12
(Bugzilla: Unauthorized access and information disclosure)


    Bugzilla allows any user to modify the flags of any bug
    (CVE-2005-2173). Bugzilla inserts bugs into the database before marking
    them as private, in connection with MySQL replication this could lead
    to a race condition (CVE-2005-2174).
  
Impact

    By manually changing the URL to process_bug.cgi, a remote attacker
    could modify the flags of any given bug, which could trigger an email
    including the bug summary to be sent to the attacker. The race
    condition when using Bugzilla with MySQL replication could lead to a
    short timespan (usually less than a second) where the summary of
    private bugs is exposed to all users.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2173
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2174
    http://www.bugzilla.org/security/2.18.1/


Solution: 
    All Bugzilla users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/bugzilla-2.18.3"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-12] Bugzilla: Unauthorized access and information disclosure");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Bugzilla: Unauthorized access and information disclosure');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/bugzilla", unaffected: make_list("ge 2.18.3"), vulnerable: make_list("lt 2.18.3")
)) { security_warning(0); exit(0); }
