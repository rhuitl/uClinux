# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14534);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200407-01");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200407-01
(Esearch: Insecure temp file handling)


    The eupdatedb utility uses a temporary file (/tmp/esearchdb.py.tmp) to
    indicate that the eupdatedb process is running. When run, eupdatedb checks
    to see if this file exists, but it does not check to see if it is a broken
    symlink. In the event that the file is a broken symlink, the script will
    create the file pointed to by the symlink, instead of printing an error and
    exiting.
  
Impact

    An attacker could create a symlink from /tmp/esearchdb.py.tmp to a
    nonexistent file (such as /etc/nologin), and the file will be created the
    next time esearchdb is run.
  
Workaround

    There is no known workaround at this time. All users should upgrade to the
    latest available version of esearch.
  

Solution: 
    All users should upgrade to the latest available version of esearch, as
    follows:
    # emerge sync
    # emerge -pv ">=app-portage/esearch-0.6.2"
    # emerge ">=app-portage/esearch-0.6.2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200407-01] Esearch: Insecure temp file handling");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Esearch: Insecure temp file handling');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-portage/esearch", unaffected: make_list("ge 0.6.2"), vulnerable: make_list("le 0.6.1")
)) { security_warning(0); exit(0); }
