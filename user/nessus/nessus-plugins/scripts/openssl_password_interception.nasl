#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>,
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11267);
 script_version("$Revision: 1.24 $");

 script_cve_id("CVE-2003-0078", "CVE-2003-0131", "CVE-2003-0147");
 script_bugtraq_id(6884, 7148);
 script_xref(name:"OSVDB", value:"3945");
 script_xref(name:"RHSA", value:"RHSA-2003:101-01");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:024");
 
 name["english"] = "OpenSSL password interception";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using a version of OpenSSL which is
older than 0.9.6j or 0.9.7b

This version is vulnerable to a timing based attack which may
allow an attacker to guess the content of fixed data blocks and
may eventually be able to guess the value of the private RSA key
of the server.

An attacker may use this implementation flaw to sniff the
data going to this host and decrypt some parts of it, as well
as impersonate your server and perform man in the middle attacks.

*** Nessus solely relied on the banner of the remote host
*** to issue this warning

See also : http://www.openssl.org/news/secadv_20030219.txt
	   http://lasecwww.epfl.ch/memo_ssl.shtml
	   http://eprint.iacr.org/2003/052/

Solution : Upgrade to version 0.9.6j (0.9.7b) or newer
Risk factor : Medium";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of OpenSSL";
 summary["francais"] = "Verifie la version de OpenSSL";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 if ( defined_func("bn_random") )
  script_dependencie("mandrake_MDKSA-2003-020.nasl", "redhat-RHSA-2003-063.nasl", "suse_SA_2003_011.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here - we rely on Apache to spit OpenSSL's
# version. That sucks.
#

include("http_func.inc");
include("misc_func.inc");

if ( get_kb_item("CVE-2003-0078") ) exit(0);

ports = add_port_in_list(list:get_kb_list("Services/www"), port:443);

foreach port (ports)
{
 banner = get_http_banner(port:port);
 if ( ! banner ) exit(0);
 if(egrep(pattern:"^Server.*OpenSSL/0\.9\.([0-5][^0-9]|6[^a-z]|6[a-i])", string:banner) || egrep(pattern:"^Server.*OpenSSL/0\.9\.7(-beta|a| )", string:banner)) security_warning(port);
}
