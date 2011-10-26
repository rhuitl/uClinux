#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

An FTP server is listening on this port

Description :

It is possible to obtain the banner of the remote FTP server
by connecting to the remote port.

Risk factor : 

None";

if(description)
{
 script_id(10092);
 script_version ("$Revision: 1.26 $");
 name["english"] = "FTP Server Detection";
 script_name(english:name["english"]);
 

 script_description(english:desc["english"]);
 
 summary["english"] = "Connects to port 21";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Service detection";
 script_family(english:family["english"]);
 script_require_ports("Services/ftp", 21);
 script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl");
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (!port) port = 21;

banner = get_ftp_banner(port: port);

if(banner)
{
 if("NcFTPd" >< banner)set_kb_item(name:"ftp/ncftpd", value:TRUE);
 if(egrep(pattern:".*icrosoft FTP.*",string:banner))set_kb_item(name:"ftp/msftpd", value:TRUE);
 if(egrep(pattern:".*heck Point Firewall-1 Secure FTP.*", string:banner))set_kb_item(name:"ftp/fw1ftpd", value:TRUE);
 if(egrep(pattern:".*Version wu-.*", string:banner))set_kb_item(name:"ftp/wuftpd", value:TRUE);
 if(egrep(pattern:".*xWorks.*", string:banner))set_kb_item(name:"ftp/vxftpd", value:TRUE);

 report = desc["english"] + '\n\nPlugin output :\n\nThe remote FTP banner is :\n' + banner;
 security_note(port:port, data:report);
}
