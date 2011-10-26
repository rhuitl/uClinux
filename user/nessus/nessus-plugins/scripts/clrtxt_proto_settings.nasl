#TRUSTED 6c82f7602c3d98aeb3e26d74185c0b893980baf07cbdc7d98c53909661ff89aec5c51ce8ea2217099d2d1a9ba5bf262a96a439b4639ebaf7fa7e6e150ca7be8283b5e194cabdfff2e0672179ebecc0363827e6964bcfc96a580666be036509d58be26199437fd77b695b20cad6b37a49af98bbcded72f6b29d237081b25c2da84105dd4a41fd14a43350f4ba9aa51335ba7a7b296df341b4db22b3977fb0078933a56cd6f126b72c10628cf4b8b6cc31ea6232c7782fec2771d7bcfa3423f2d1de4b09398b01b2a718eac4b736b554abdf3ee3bfee814af1770e080aa95f4c0da8ab9e761a9a1ae1c93967c8a0c0fc48b62159cc372cc8cb0854a5d15be6075b3cb31b0e9a4e18be8709e8ba048b266972fceb870b1fed21bf0c4b7924714a4a4cea6b7979b89b9b3486ffe639f9995667e4c36ba4ae56b4e7654706eb8f112b17562c61ed1a5c4e446cc0bd7e0995092d560ae11621a6470dadcc33ebf5d0cf3f63839f423972b7cb3e6fcf5171cc498b14feccb891c51e237544fd36d36165f127dfdc3c15b23d7b49d70a0555fd12037d375a0a4c3d478fe78e4318e785d5ef20adc6168072e1da0efe2f38f6674741ac40412830c62ffab5c26686405f1504d8a18045ba008c1a9e4d0f61eed7e82dcb23d80a4e8c2297df56fd857e6c327e906adbe7f304d0019525c5d7603d8ac84600067240c176b3e908e658752b07


if(description)
{
 script_id(21744);
 script_version ("1.0");
 name["english"] = "Cleartext protocols settings";
 desc["english"] = "
This script just sets global variables (telnet/rexec/rsh logins and passwords)
which are then used to perform host-level patch level checks.

You should avoid using these clear text protocols when doing a scan
as Nessus will basically broadcast the password to every tested host.

Risk factor: None";
 script_description(english:name["english"]);
 script_name(english:name["english"]);
 family["english"] = "Settings";
 script_family(english:family["english"]);
 
 summary["english"] = "set clear text credentials to perform local security checks";
 script_summary(english:summary["english"]);
 script_copyright(english:"Copyright (C) 2006 Tenable");
 script_category(ACT_INIT);
 script_add_preference(name:"User name : ", type:"entry", value:"");
 script_add_preference(name:"Password (unsafe!) : ", type:"password", value:"");
 script_add_preference(name:"Try to perform patch level checks over telnet", type:"checkbox", value:"no");
 #script_add_preference(name:"Try to perform patch level checks over rlogin", type:"checkbox", value:"no");
 script_add_preference(name:"Try to perform patch level checks over rsh", type:"checkbox", value:"no");
 script_add_preference(name:"Try to perform patch level checks over rexec", type:"checkbox", value:"no");
 exit(0);
}

account    = script_get_preference("User name : ");
password   = script_get_preference("Password (unsafe!) : ");

try_telnet = script_get_preference("Try to perform patch level checks over telnet");
#try_rlogin = script_get_preference("Try to perform patch level checks over rlogin");
try_rsh    = script_get_preference("Try to perform patch level checks over rsh");
try_rexec  = script_get_preference("Try to perform patch level checks over rexec");

if ( account  ) set_kb_item(name:"Secret/ClearTextAuth/login", value:account);
if ( password ) set_kb_item(name:"Secret/ClearTextAuth/pass", value:password);

if ( try_telnet == "yes" ) set_kb_item(name:"HostLevelChecks/try_telnet", value:TRUE);
#if ( try_rlogin == "yes" ) set_kb_item(name:"HostLevelChecks/try_rlogin", value:TRUE);
if ( try_rsh    == "yes" ) set_kb_item(name:"HostLevelChecks/try_rsh",    value:TRUE);
if ( try_rexec  == "yes" ) set_kb_item(name:"HostLevelChecks/try_rexec",    value:TRUE);
