# Written by Renaud Deraison <deraison@nessus.org>
#
#
# This plugin uses the data collected by webmirror to display the list
# of files that may not be suitable to be distributed over the web as
# they may be used for intelligence purposes.


if(description)
{
 script_id(11419);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "Office files list";
 script_name(english:name["english"]);
 
 desc["english"] = "
This script displays the list of .xls, .ppt, .doc and .pdf files that
are available on the remote server.

Distributing such files over the web can be done, but the webmaster
should make sure that they contain no confidential data.";


 script_description(english:desc["english"]);
 
 summary["english"] = "Displays office files";
 
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl", "webmirror.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


function test_files(files)
{
 local_var f, req, soc, r, retf;
 
 retf = make_list();
 foreach f (files)
 {
  req = http_get(item:f, port:port);
  soc = http_open_socket(port);
 
  if(!soc)exit(0);
  
  send(socket:soc, data:req);
  r  = recv_line(socket:soc, length:4096);
  close(soc);
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:r)){
  	retf = make_list(retf, f);
	}
 }
 return retf;
}


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

report = "";

software["doc"] = "Word";
software["wri"] = "Write";
software["xls"] = "Excel";
software["ppt"] = "PowerPoint";
software["csv"] = "spreadsheet";
software["dif"] = "spreadsheet";
software["rtf"] = "word processor";
software["pdf"] = "Acrobat";
software["sxw"] = "OO Writer";
software["sxi"] = "00 Presentation";
software["sxc"] = "00 Spreadsheet";
software["sdw"] = "StarWriter";
software["sdd"] = "StarImpress";
software["sdc"] = "StarCalc";

foreach ext(keys(software))
{
 t = get_kb_list(string("www/", port, "/content/extensions/", ext));
if(!isnull(t)){
 t = test_files(files:make_list(t));
 word = NULL;
 foreach f (t)
 {
  word += '   ' + f + '\n';
 }
 if(word)
  report += 'The following ' + software[ext] + ' files (.' + ext + ') are available on the remote server : \n' + word;
 }
}

if (report)
{
 report += '
 
You should make sure that none of these files contain confidential or
otherwise sensitive information.

An attacker may use these files to gain a more intimate knowledge of
your organization and eventually use them do perform social engineering
attacks (abusing the trust of the personnel of your company).

Solution : sensitive files should not be accessible by everyone, but only
by authenticated users.';

 security_note(port:port, data:report);
}
