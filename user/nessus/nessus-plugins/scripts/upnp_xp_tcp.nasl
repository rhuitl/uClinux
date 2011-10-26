#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11765);
 script_bugtraq_id(3723);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2001-0876");
 
 name["english"] = "scan for UPNP/Tcp hosts";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running Microsoft UPnP TCP helper.

If the tested network is not a home network, you should disable
this service.

Solution : Set the following registry key :
                Location : HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV
                Key      : Start
                Value    : 0x04


Risk factor : Low";


 script_description(english:desc["english"]);

 summary["english"] = "UPNP/tcp scan";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_require_ports(5000);
 exit(0);
}


include('global_settings.inc');

if ( report_paranoia < 1 ) exit(0);

if(get_port_state(5000))
{
 soc = open_sock_tcp(5000);
 if( !soc)exit(0);
 send(socket:soc, data:'\r\n\r\n');
 r = recv_line(socket:soc, length:4096);
 if("HTTP/1.1 400 Bad Request" >< r) 
 {
 	security_warning(5000);
 }
}
