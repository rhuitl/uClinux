#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from
# (C) Tenable Network Security
#
# Ref: Bernardo Quintero of Hispasec <bernardo@hispasec.com>
#
# This script is released under the GNU GPLv2


if(description)
{
 script_id(14597);
 script_bugtraq_id(547);
 script_cve_id("CVE-1999-1078");
 script_version("$Revision: 1.4 $");

 name["english"] = "WS_FTP client weak stored password";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host has a version of the WS_FTP client which use a weak
encryption method to store site password.

Solution : Upgrade to the newest version of the WS_FTP client 
See also : http://www.ipswitch.com/
Risk factor : Medium";


 script_description(english:desc["english"]);

 summary["english"] = "Check IPSWITCH WS_FTP version";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Windows";
 script_family(english:family["english"]);

 script_dependencies("ws_ftp_client_overflows.nasl");
 script_require_keys("ws_ftp_client/version");

 exit(0);
}

# start script

version = get_kb_item("ws_ftp_client/version");
if ( ! version ) exit(0);

if (ereg(string:version, pattern:"^([0-5]\.[0-9]\.[0-9]|6\.0\.0\.0[^0-9])")) security_warning(port); 
