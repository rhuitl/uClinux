#TRUSTED 4391612dbbc162e10c55f2e254f8a00eb14e2d71af335f78cab390aa72b8e7594ab477192d15008bd37446539c6dc2ee59e0bd89657a1cae67356465037798bf45e18bfd8e1ffb3aa9049cf7b6bc9bf8f06d3746043295a5a62837de7333ece3a1a32d1ba6087a974ce63a503c28981d230568537c1ae8ca3082ab53a6f8cf057f6070234b66f735d65d12c647de33aae57ef5fb3b25ea12f2676d3aebb3113e701e31ac99a4c483fd534a4ca7a31f283e18bbc5e68067eb35f03ff805c8989381e5844f0f8c5295612e037d85a81b7c4d7de92a5a08986a9dfe0730b14809302dba4a6c24b1d440d01a9e7a6e3291b7d310241db2e462961d6ca0b366d1bb43f24269838bd25859912760a133f1802dc1b8b8bb3055fa2876e7f809c96cfa3eac76ae040978777ebca3c3b0c0359aa5d17bcf4a7010fc11d1225d2047bded6b137d6973d93d8b3179c957f809945fda32b79ebf970dcfae795f31d041a7e53b735148f723350470aaf72f1e4f5fac70c1ae2fd39a2de69a6da4f5d7013fb6b39e42d91bd00a880e5934deab562665cb841d45932bf312a7e813d07f22df31ae0ae1d4e2d86e036fb30027692bf62fca05e49e318c6bf648031f4bc6bee31be396421b1d852fcb50fbcf4d500e8ac95c38de66b1ac4567ef177b17d7d3185d2aeaf09d80f9a6cb4207176b8acb1c1038d59d61c6017cb1b6d5ef55a57592d091
#
# (C) Tenable Network Security
#

if ( NASL_LEVEL < 2202 ) exit(0);

if(description)
{
 script_id(17351);
 script_version ("1.1");
 name["english"] = "Kerberos configuration";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin lets a user enter information about the Kerberos server
which will be queried by some scripts (SMB at this time) to log into 
the remote hosts.

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Fills kerberos information in the KB";
 script_summary(english:summary["english"]);
 
 script_category(ACT_SETTINGS);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Settings";
 family["francais"] = "Configuration";
 script_family(english:family["english"], francais:family["francais"]);
 
 script_add_preference(name:"Kerberos Key Distribution Center (KDC) :", type:"entry", value:"");
 script_add_preference(name:"Kerberos KDC Port :", type:"entry", value:"88");
 script_add_preference(name:"Kerberos KDC Transport :", type:"radio", value:"udp;tcp");
 script_add_preference(name:"Kerberos Realm (SSH only) :", type:"entry", value:"");
 exit(0);
}



kdc = script_get_preference("Kerberos Key Distribution Center (KDC) :");
if ( ! kdc ) exit(0);

kdc_port = int(script_get_preference("Kerberos KDC Port :"));
if ( kdc_port <= 0 ) exit(0);

kdc_realm = script_get_preference("Kerberos Realm (SSH only) :");
if ( kdc_realm ) set_kb_item(name:"Secret/SSH/realm", value:kdc_realm);

set_kb_item(name:"Secret/kdc_hostname", value:kdc);
set_kb_item(name:"Secret/kdc_port", value:kdc_port);

kdc_transport =  script_get_preference("Kerberos KDC Transport :");
if ( kdc_transport == "tcp" ) 
 set_kb_item(name:"Secret/kdc_use_tcp", value:TRUE);


