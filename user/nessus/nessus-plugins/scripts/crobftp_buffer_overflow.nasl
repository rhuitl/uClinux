#Copyright (C) 2004 Tenable Network Security
#


if(description)
{
 script_id(12060);
 script_cve_id("CVE-2004-0282");
 script_bugtraq_id(9651);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"6621");
 }
 script_version ("$Revision: 1.5 $");

 name["english"] = "CROB FTP Server multiple connections DoS";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running CROB FTP server.

There is a bug in the way this server handles multiple connection
requests which may allow an attacker to trigger a remote Denial of
Service (DoS) attack against the server.

Solution : Upgrade CROB FTP server
Risk factor : High";


 script_description(english:desc["english"]);


 script_summary(english:"CROB Remote DoS");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");


 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

 script_require_ports("Services/ftp", 21);
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl");

 exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);


# 220-Crob FTP Server V3.5.2
#220 Welcome to Crob FTP Server.
if(egrep(pattern:"Crob FTP Server V(3\.([0-4]\.*|5\.[0-2])|[0-2]\..*)", string:banner)) security_hole(port);

