#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# The HTTP IDS evasion mode comes from Whisker, by RFP.
# Read http://www.wiretrip.net/rfp/pages/whitepapers/whiskerids.html
#
# GPL, blah blah blah
# See the Nessus Scripts License for details
#


if ( NASL_LEVEL >= 3000 ) exit(0);

if(description)
{
 script_id(10890);
 script_version ("$Revision: 1.13 $");

 name["english"] = "HTTP NIDS evasion";
 name["francais"] = "Fonctions HTTP Anti NIDS (détecteur d'intrusions)";
 
 script_name(english:name["english"],
            francais:name["francais"]);
 
 desc["english"] = "
This plugin configures Nessus for NIDS evasion (see the 'Prefs' panel).
NIDS evasion options are useful if you want to determine
the quality of the expensive NIDS you just bought.

HTTP evasion techniques :
- HEAD: use HEAD method instead of GET
- URL encoding:
 - Hex: change characters to %XX
 - MS UTF-16: change characters to %uXXXX. This works only with IIS.
 - UTF-16: change characters to %00%XX. This should *not* work!
 - Broken UTF-8: change characters to invalid multibyte UTF8 sequences.
- Absolute URI: insert scheme://host/ in front of the relative URI.
- Double slashes: change every / to //
- Reverse traversal: change / into /dirname/../
  'Basic' inserts 8 characters random directory names; 'Long' means 1000 
  character directory name.
- Self-reference: changes every / to /./
- Premature request ending: just like 'reverse traversal', but the directory 
  name contains %0d%0a (could be translated to CR LF)
- CGI.pm: uses ';' instead of '&' in the query string.
- Parameter hiding: another form of reverse traversal. The directory contains
  %3F (could be translated to ?)
- Dos/Windows: uses \ instead of /
- Null method: insert %00 between the method and the URI
- TAB: uses TAB instead of SPACE between the method, the URL and the HTTP 
  version
- HTTP/0.9: uses HTTP/0.9 requests (method & URI only, no HTTP version field)

'Premature request ending' and 'Parameter hiding' target 'smart' IDS.

Read http://www.wiretrip.net/rfp/pages/whitepapers/whiskerids.html
for more information.

Warning: those features are experimental and some 
options may result in false negatives!
This plugin does not do any security check.

Risk factor : None";


 script_description(english:desc["english"]);
 
 summary["english"] = "NIDS evasion options";
 summary["francais"] = "Options anti NIDS";
 script_summary(english:summary["english"],
               francais:summary["francais"]);
 
 script_category(ACT_SETTINGS);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi / Renaud Deraison");
 family["english"] = "Settings";
 family["francais"] = "Configuration";
 script_family(english:family["english"], francais:family["francais"]);
 
 script_add_preference(name:"HTTP User-Agent", type:"entry", value:"");
 script_add_preference(name:"Use HTTP HEAD instead of GET", type:"checkbox", value:"no");
 script_add_preference(name:"URL encoding", type:"radio", value:"none;Hex;UTF-16 (double byte); UTF-16 (MS %u);Incorrect UTF-8");
 # Pavel kankovsky's suggestion
 script_add_preference(name:"Absolute URI type", type:"radio", value:"none;file;gopher;http");
 script_add_preference(name:"Absolute URI host", type:"radio", value:"none;host name;host IP;random name;random IP");

 script_add_preference(name:"Double slashes", type:"checkbox", value:"no");
 script_add_preference(name:"Reverse traversal", type:"radio", value:"none;Basic;Long URL");

 script_add_preference(name:"Self-reference directories", type:"checkbox", value:"no");
 script_add_preference(name:"Premature request ending", type:"checkbox", value:"no");
# CGI.pm "anti NIDS" discovered by Securiteam
 script_add_preference(name:"CGI.pm semicolon separator", type:"checkbox", value:"no");
 script_add_preference(name:"Parameter hiding", type:"checkbox", value:"no");
 script_add_preference(name:"Dos/Windows syntax", type:"checkbox", value:"no");
 script_add_preference(name:"Null method", type:"checkbox", value:"no");
 script_add_preference(name:"TAB separator", type:"checkbox", value:"no");
 script_add_preference(name:"HTTP/0.9 requests", type:"checkbox", value:"no");

 script_add_preference(name:"Force protocol string : ", type:"entry", value:"");
 script_add_preference(name:"Random case sensitivity (Nikto only)", type:"checkbox", value:"no");
 exit(0);
}

# TBD: Implement "Random case sensitivity" from Nikto

whisker_nids = 'X';

opt = script_get_preference("HTTP User-Agent");
if (opt)
  set_kb_item(name:"http/user-agent", value:opt);

opt = script_get_preference("Use HTTP HEAD instead of GET");
warn = 0;

if(opt == "yes")
{
set_kb_item(name:"NIDS/HTTP/head", value:"yes");
warn = 1;
}

opt = script_get_preference("URL encoding");
if("none" >< opt)opt = 0;

if(opt)
{
 set_kb_item(name:"NIDS/HTTP/URL_encoding", value:opt);
 whisker_nids = '1';
 warn = 1;
}


opt = script_get_preference("Double slashes");

if(opt == "yes")
{
	set_kb_item(name:"NIDS/HTTP/double_slash", value:"yes");
	warn = 1;
}

opt = script_get_preference("Reverse traversal");
if("none" >< opt)opt = 0;

if (opt)
{
 if (opt == "Basic") 
 {
 	set_kb_item(name:"NIDS/HTTP/reverse_traversal", value:8);
	warn = 1;
 }
 if (opt == "Long URL") 
 {
 	set_kb_item(name:"NIDS/HTTP/reverse_traversal", value:1000);
	warn = 1;
	whisker_nids = '4';
 }
}


opt = script_get_preference("Absolute URI type");


if(opt && !("none" >< opt))
{
set_kb_item(name:"NIDS/HTTP/absolute_URI/type", value:opt);
warn = 1;
}



opt = script_get_preference("Absolute URI host");


if(opt && !("none" >< opt))
{
  set_kb_item(name:"NIDS/HTTP/absolute_URI/host", value:opt);
  warn = 1;
}


opt = script_get_preference("Self-reference directories");
if(opt == "yes")
{
 set_kb_item(name:"NIDS/HTTP/self_ref_dir", value:"yes");
 whisker_nids = '2';
 warn = 1;
}


opt = script_get_preference("Dos/Windows syntax");
if(opt == "yes")
{
 set_kb_item(name:"NIDS/HTTP/dos_win_syntax", value:"yes");
 warn = 1;
 whisker_nids = '8';
}


opt = script_get_preference("Null method");
if(opt == "yes")
{
 set_kb_item(name:"NIDS/HTTP/null_method", value:"yes");
 warn = 1;
}



opt = script_get_preference("TAB separator");
if(opt == "yes")
{
 set_kb_item(name:"NIDS/HTTP/tab_separator", value:"yes");
 warn = 1;
 whisker_nids = '6';
}


opt = script_get_preference("HTTP/0.9 requests");

if(opt == "yes")
{
 set_kb_item(name:"NIDS/HTTP/http09", value:"yes");
 warn = 1;
}


opt = script_get_preference("Premature request ending");
if(opt == "yes")
{
 set_kb_item(name:"NIDS/HTTP/premature_request_ending", value:"yes");
 warn = 1;
 whisker_nids = '3';
}


opt = script_get_preference("CGI.pm semicolon separator");

if(opt == "yes")
{
set_kb_item(name:"NIDS/HTTP/CGIpm_param", value:"yes");
warn = 1;
}

opt = script_get_preference("Parameter hiding");
if(opt == "yes")
{
 set_kb_item(name:"NIDS/HTTP/param_hiding", value:"yes");
 warn = 1;
 whisker_nids = 5;
}


p = script_get_preference("Force protocol string : ");
if(p && (p != "no"))
{
 set_kb_item(name:"NIDS/HTTP/protocol_string", value:p);
 warn = 1;
}

opt = script_get_preference("Random case sensitivity (Nikto only)");
if(opt == "yes")
{
 set_kb_item(name:"NIDS/HTTP/random_case", value: "yes");
 whisker_nids = 7;
 #warn = 1;
}

set_kb_item(name:"/Settings/Whisker/NIDS", value:string(whisker_nids));

if(warn)
{
w="HTTP NIDS evasion functions are enabled. 
You may get some false negative results";
 security_note(port:0, data:w);
}
