#
# (C) Tenable Network Security
#

if (description)
{
 script_id(12098);
 script_cve_id("CVE-2004-0148");
 script_bugtraq_id(9832);
 if (defined_func("script_xref")) script_xref(name:"RHSA", value:"RHSA-2003:307-01");

 script_version("$Revision: 1.4 $");
 name["english"] = "wu-ftpd restricted-gid unauthorized access";
 script_name(english: name["english"]);

 desc["english"] = "
The remote host is running wu-ftpd 2.6.2 or older.

There is a bug in this version which may allow an attacker to bypass the
'restricted-gid' feature and gain unauthorized access to otherwise restricted
directories.

*** Nessus solely relied on the banner of the remote FTP server, so this might
*** be a false positive.

Solution : There is no official fix at this time. See the RedHat advisories
for more information.

Risk factor : High";

 script_description(english: desc["english"]);
 script_summary(english: "Checks the remote Wu-ftpd version");

 script_category(ACT_GATHER_INFO);
 script_family(english: "FTP");

 script_copyright(english: "Copyright (C) 2004 Tenable Network Security");
 script_dependencie("find_service_3digits.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}


#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if(egrep(pattern:"^220.*wu-((1\..*)|2\.([0-5]\..*|6\.[0-2]))", string:banner, icase:TRUE))
        security_hole(port);
