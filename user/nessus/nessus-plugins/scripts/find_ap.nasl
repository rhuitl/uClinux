# Copyright 2002 by John Lampe...j_lampe@bellsouth.net
# thanks for signatures and packet dumps from Matt N., William Craig,
# Bill King, jay at kinetic dot org,  HD Moore
#
# Modifications by rd: don't use forge_udp_packet() but use a regular
# udp socket instead ; use Nessus's SNMP functions, don't hardcode the
# use of the "public" SNMP community. Use SNMP/sysDesc is present already,
# simplified the search through the sysDesc string.
#
#

#
# See the Nessus Scripts License for details
#
#

desc["english"] = "
The remote host is a Wireless Access Point.  

You should ensure that the proper physical and logical controls exist
around the AP.  A misconfigured access point may allow an attacker to
gain access to an internal network without being physically present on 
the premises.  If the access point is using an 'off-the-shelf' configuration
(such as 40 or 104 bit WEP encryption), the data being passed through the 
access point may be vulnerable to hijacking or sniffing. 

Risk factor : Low";


if(description)
{
 script_id(11026);
 script_version ("$Revision: 1.47 $");

 name["english"] = "Access Point detection";
 script_name(english:name["english"]);


 script_description(english:desc["english"]);

 summary["english"] = "
Detects wireless access points present via TCP/IP Nmap fingerprint, 
analysis of HTTP management interface, analysis of FTP banner and
analysis of SNMP information present";

 script_summary(english:"Detects Wireless APs");

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002 John Lampe / Ron Gula / Stan Scalsky (Tenable Network Security)");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("snmp_sysDesc.nasl", "http_version.nasl");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

# list of NMAP tcp fingerprints which indicate a WAP (broken)
# current list as of nmap-3.50

tcpfinger[1] = "2Wire Home Portal 100 residential gateway";
tcpfinger[2] = "Aironet AP4800E";
tcpfinger[3] = "Apple Airport Extreme Base Station";
tcpfinger[4] = "BenQ Wireless Lan Router";
tcpfinger[5] = "Cisco 360 Access Point";
tcpfinger[6] = "Cisco 1200 access point";
tcpfinger[7] = "Cisco Aironet WAP";
tcpfinger[8] = "Cisco AP1220";
tcpfinger[9] = "Datavoice 3Com WAP";
tcpfinger[10] = "D-Link 704P Broadband Gateway or DI-713P WAP";
tcpfinger[11] = "D-Link DI-713P Wireless Gateway";
tcpfinger[12] = "D-Link DI-series, Sitecom BHS WAP";
tcpfinger[13] = "D-Link DRC-1000AP or 3com Access Point 2000";
tcpfinger[14] = "D-Link DWL-5000AP";
tcpfinger[15] = "D-Link, SMC, Tonze, or US Robotics wireless broadband router";
tcpfinger[16] = "Fiberline WL-1200R1";
tcpfinger[17] = "Linksys WET-11";
tcpfinger[18] = "Linksys BEFW11S4 WAP or BEFSR41 router";
tcpfinger[19] = "Linksys WAP11 Wireless AP";
tcpfinger[20] = "Linksys WAP11 or D-Link DWL-900+";
tcpfinger[21] = "Linksys, D-Link, or Planet WAP";
tcpfinger[22] = "Netgear DG824M WAP";
tcpfinger[23] = "Netgear FM144P";
tcpfinger[24] = "Netgear MR314";
tcpfinger[25] = "Netgear MR814";
tcpfinger[26] = "Panasonic network camera or SMC WAP";
tcpfinger[27] = "Planet WAP 1950 Wireless Access Point";
tcpfinger[28] = "SMC Barricade or D-Link DL-707 Wireless Broadband Router";
tcpfinger[29] = "SMC Barricade Wireless Broadband Router";
tcpfinger[30] = "SMC Barricade DSL Router/Modem/Wireless AP";
tcpfinger[31] = "SMC Barricade Router";
tcpfinger[32] = "Symbol/Spectrum24 wireless AP";
tcpfinger[33] = "US Robotics USR8022 broadband wireless router";
tcpfinger[34] = "US Robotics broadband router";
tcpfinger[35] = "Zcomax Wireless Access Point";
tcpfinger[36] = "ZoomAir IG-4165 wireless gateway";

# Wireless Bridges
tcpfinger[37] = "Aironet 630-2400";
tcpfinger[38] = "Aironet Wireless Bridge";
tcpfinger[39] = "ARLAN BR2000E V5.0E Radio Bridge";
tcpfinger[40] = "BreezeCOM BreezeACCESS wireless bridge";
tcpfinger[41] = "Cisco AIR-WGB340";
tcpfinger[42] = "Cisco WGB350";
tcpfinger[43] = "Linksys WET-11 wireless ethernet bridge";
tcpfinger[44] = "Linksys WGA54G";
tcpfinger[45] = "Proxim Stratum MP wireless bridge";

# This one will cause lots of false positives since the full signature is:
#  Embedded device: HP Switch, Copper Mountain DSL Concentrator, Compaq 
#  Remote Insight Lights-Out remote console card, 3Com NBX 25 phone 
#  system or Home Wireless Gateway, or TrueTime NTP clock

tcpfinger[46] = "3Com NBX 25 phone system or Home Wireless Gateway";


pre = "The remote host is a Wireless Access Point (";

warning = string(").\n\nYou should ensure that the proper physical and logical
controls exist around the AP.  A misconfigured access point may allow an
attacker to gain access to an internal network without being physically
present on the premises.  If the access point is using an 'off-the-shelf'
configuration (such as 40 or 104 bit WEP encryption), the data being 
passed through the access point may be vulnerable to hijacking
or sniffing.

Risk factor : Low");

os = get_kb_item("Host/OS");
if( os )
{
  for (i=1; tcpfinger[i]; i = i + 1) {
	if (tcpfinger[i] >< os ) {
		security_warning(port:0, data:pre+os+warning);
		exit(0);
		}
	}
}

# try to find APs via web management interface
port = get_http_port(default:80);

sigs = make_list(
# "WLAN",    # SMC, risky
 "SetExpress.shm",   #cisco 350
 "D-Link DI-1750",
 "D-Link DI-824",
 "D-Link DI-784",
 "D-Link DI-774",
 "D-Link DI-764",
 "D-Link DI-754",
 "D-Link DI-714",
 "D-Link DI-713",
 "D-Link DI-624",
 "DI-624+",
 "D-Link DI-614",
 "D-Link DI-524",
 "D-Link DI-514",
 "D-Link DSA-3100",
 "Cisco AP340",
 "Cisco AP350",
 "Linksys WAP",
 'Linksys WRT',
 "Linksys BEFW",
 "Linksys WPG",
 "Linksys WRV",
 "SOHO Version",
 'realm="BUFFALO WBR-G54"',
 'WWW-Authenticate: Basic realm="R2 Wireless Access Platform"',
 'realm="MR814',
 'realm="FM114P',
 'realm="MA101',
 'realm="MR314',
 'realm="ME102',
 'realm="DG824M',
 'realm="DG834G',
 'realm="PS111W',
 'realm="CG814M',
 'realm="FVM318',
 'realm="ME103',
 'realm="HE102',
 'realm="HR314',
 'realm="Ral-WAP3"',    # Linksys WRT-54G Wireless-G Router, from Jeff Mercer
 'realm="WG101',
 'realm="WG302',
 'realm="WG602',
 'realm="WGR614',
 'realm="FWAG114',
 'realm="FM114P',
 'realm="WKPC',
 'realm="WCG',
 'realm="WET',
 'realm="BEFW',
 'realm="WAP11',
 'realm="WAP51',
 'realm="WAP54',
 'realm="WAP55',
 'realm="WRT54',
 'realm="WRT55',
 'realm="WRT300',
 'realm="WRV200',
 'realm="WRTSL',
 "BCM430",		# Broadcom chips (?)
 "OfficePortal 1800HW",
 "HomePortal 180HW",
 "Portal 1000HG",
 "Portal 1000HW",
 "Portal 1000SW",
 "Portal 1700HG",
 "Portal 1700HW",
 "Portal 1700SG",
 "HomePortal 180HG",
 "HomePortal 2000",
 "Wireless 11a/b/g Access Point",
 "AT-WA1004G",
 "AT-WA7500",
 "AT-WL2411",
 "RTW020",
 "RTA040W",
 "RTW010",
 "The setup wizard will help you to configure the Wireless",
 'realm="Access-Product',
 "USR8054",
 "WGR614",
 "WGR624",
 "Linksys WET11",
 "wireless/wireless_tab1.jpg",
 "wireless/use_as_access_point",
 "Gateway 11G Router",
 "Gateway 11B Router",
 "MN-500",
 "MN-700",
 "MN-510",
 "SBG900",
 "SBG1000",
 "WA840G",
 "WL1200-AB",
 "WL5400AP",
 # jwlampe@nessus.org adds on 5.19.2006
 "LANCOM Wireless L-11",
 "LANCOM L-54g Wireless",
 "LANCOM L-54ag Wireless",
 "Linksys BEFW11",
 "Server: DCS-",
 "Cisco WGB350",
 "Wi-LAN AWE"
 );



if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc) {
  send(socket:soc, data:http_get(item:"/", port:port));
  answer = http_recv(socket:soc);
  http_close_socket(soc);
  if (answer) {
    foreach sig (sigs) {
          if ( sig >< answer ) { 
              security_warning(port:0, data:pre+sig+warning);
              exit(0);
          }
    }
  }
 }
}


# try find APs via ftp
port = 21;
ftppos[0] = "Cisco BR500";
ftppos[1] = "WLAN AP";
ftppos[2]= "ireless";
 # jwlampe@nessus.org adds on 5.19.2006
ftppos[3] = "DCS-5300G";
ftppos[4] = "DCS-5300W";
ftppos[5] = "DCS-6620G";


if(get_port_state(port))
{
soc = open_sock_tcp(port);
if (soc) {
  r = recv_line(socket:soc, length:512);
  close(soc);
  if (r) {
      for (i=0; ftppos[i]; i = i + 1) {
          if ( ftppos[i] >< r ) 
	  {
               security_warning(port:0, data:pre+ftppos[i]+warning);
               exit(0);
          }
      }
  }
 }
}




# try to find APs via telnet
port = 23;
telnetpos[0] = "DCS-3220G telnet daemon";
telnetpos[1] = "DCS-5300G Telnet Daemon";
telnetpos[2] = "DCS-5300W Telnet Daemon";
telnetpos[3] = "DCS-6620G telnet daemon";
telnetpos[4] = "ink Corp. Access Point";
telnetpos[5] = "WLSE";
telnetpos[6] = "Cisco BR500E";
telnetpos[7] = "Cisco WGB350";
telnetpos[8] = "Wi-LAN AWE";
telnetpos[9] = "Lucent Access Point";
telnetpos[10]= "Wireless DSL Ethernet Switch";
telnetpos[11]= "LANCOM 1811 Wireless DSL";
telnetpos[12]= "LANCOM Wireless";
telnetpos[13] = "LANCOM L-54";
telnetpos[14] = "ADSL Wireless Router";
telnetpos[15] = "Motorola Broadband Wireless";
telnetpos[16] = "Trango Broadband Wireless";
telnetpos[17] = "Wi-LAN Hopper";
telnetpos[18] = "WANFleX Access Control";
telnetpos[19] = "Access Point Console";
telnetpos[20] = "Samsung SWL-3300AP";
telnetpos[21] = "Samsung SWL-4000";
telnetpos[22] = "Samsung SWL-6100";
telnetpos[23] = "FortiWiFi-";
telnetpos[24] = "WLAN Access Point login";
telnetpos[25] = "Wireless AP Manager Console";
telnetpos[26] = "Wireless Ethernet Adapter";
telnetpos[27] = "Avaya-Wireless-AP";
telnetpos[28] = "ORiNOCO-AP-";
telnetpos[29] = "WAP-";
telnetpos[30] = "USR5450";
telnetpos[31] = "Raylink Access Point";
telnetpos[32] = "Access Point Configuration";
telnetpos[33] = "Aircess -";
telnetpos[34] = "Netro Airstar shell";
telnetpos[35] = "Proxim AP Configuration";
telnetpos[36] = "AXXCELERA BROADBAND WIRELESS";


if ( get_port_state(port) )
{
soc = open_sock_tcp(port);
if (soc) 
{
  r = recv_line(socket:soc, length:512);
  close(soc);
  if (r) 
  {
      for (i=0; telnetpos[i]; i = i + 1) 
      {
          if ( telnetpos[i] >< r ) 
          {
               security_warning(port:0, data:pre+telnetpos[i]+warning);
               exit(0);
          }
      }
  }
 }
}



# try to find APs via snmp port (rely on them leaving public community string)


#
# Solaris comes with a badly configured snmpd which
# always reply with the same value. We make sure the answers
# we receive are not in the list of default values usually
# answered...
#
function valid_snmp_value(value)
{
 if("/var/snmp/snmpdx.st" >< value)return(0);
 if("/etc/snmp/conf" >< value)return(0);
 if( (strlen(value) == 1) && (ord(value[0]) < 32) )return(0);
 return(1);
}

community = get_kb_item("SNMP/community");
if(!community)exit(0);

if(get_udp_port_state(161))
{
 soc = open_sock_udp(161);

# put char string identifiers below
 snmppos[0]="AP-";                     # Compaq AP
 snmppos[1]="Base Station";
 snmppos[2]="WaveLan";
 snmppos[3]="WavePOINT-II";# Orinoco WavePOINT II Wireless AP
 snmppos[4]="AP-1000";     # Orinoco AP-1000 Wireless AP
 snmppos[5]="Cisco BR500"; # Cisco Aironet Wireless Bridge
 snmppos[6]="ireless";
 snmppos[7]="Internet Gateway Device"; # D-Link (fp-prone ?)


# create GET sysdescr call

mydata = get_kb_item("SNMP/sysDesc");
if(!mydata) {
 snmpobjid = raw_string(0x2b,0x06,0x01,0x02,0x01,0x01,0x01,0x00);            
 version = raw_string(0x02 , 0x01 , 0x00);
 snmplen = strlen(community) % 256;
 community = raw_string(0x04, snmplen) + community;
 pdu_type = raw_string(0xa0, 0x19);             
 request_id = raw_string(0x02,0x01,0xde);
 error_stat = raw_string(0x02,0x01,0x00);
 error_index = raw_string(0x02,0x01,0x00);
 tie_off = raw_string(0x05,0x00);


 snmpstring = version + community + pdu_type + request_id + error_stat
+ error_index + raw_string(0x30,0x0e,0x30,0x0c,0x06,0x08) + snmpobjid +
tie_off;

 tot_len = strlen(snmpstring);
 tot_len = tot_len % 256;

 snmpstring = raw_string(0x30, tot_len) +  snmpstring;

 send(socket:soc, data:snmpstring);

 mydata = recv(socket:soc, length:1025);
 if(strlen(mydata) < 48)exit(0);
 if(!mydata)exit(0);

 check_val = valid_snmp_value(value:mydata);
 if (!check_val) exit(0);
}


flag = 0;

for (psi=0; snmppos[psi]; psi = psi + 1) {
        if(snmppos[psi] >< mydata) {
            security_warning(port:0, data:pre+snmppos[psi]+warning);
            exit(0);
        }
 }
}
