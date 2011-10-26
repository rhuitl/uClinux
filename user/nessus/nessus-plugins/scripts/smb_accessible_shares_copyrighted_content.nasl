#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11777);
 script_version ("$Revision: 1.18 $");
 
 name["english"] = "SMB share hosting copyrighted material";
 script_name(english:name["english"]);
 
 desc["english"] = "
This script connects to the remotely accessible SMB shares
and attempts to find potentially copyrighted contents on it 
(such as .mp3, .ogg, .mpg or .avi files).";

 

 script_description(english:desc["english"]);
 
 summary["english"] = "Finds .mp3, .avi and .wav files";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Peer-To-Peer File Sharing";
 script_family(english:family["english"]);
 
 script_dependencies("smb_accessible_shares.nasl");
 script_require_keys("SMB/shares");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include('global_settings.inc');

if ( thorough_tests ) MaxRecursivity = 3;
else MaxRecursivity = 1;

port = kb_smb_transport();

function get_dirs(basedir, level)
{
 local_var ret,ret2, r, subdirs, subsub;
 

  if(level >= MaxRecursivity )
 	return NULL;
	
 subdirs = NULL;
 retx  = FindFirstFile(pattern:basedir + "\*");
 ret = make_list();
 while ( ! isnull(retx[1]) )
 {
 ret  = make_list(ret, retx[1]);
 retx = FindNextFile(handle:retx);
 } 
 
 if(isnull(ret))
 	return NULL;
	
 foreach r (ret)
 { 
  subsub = NULL;
  if(isnull(ret2))
  	ret2 = make_list(basedir + "\" + r);
  else
  	ret2 = make_list(ret2, basedir + "\" + r);
	
  if("." >!< r)
  	subsub  = get_dirs(basedir:basedir + "\" + r, level:level + 1);
  if(!isnull(subsub))
  {
  	if(isnull(subdirs))subdirs = make_list(subsub);
  	else	subdirs = make_list(subdirs, subsub);
  }
 }
 
 if(isnull(subdirs))
 	return ret2;
 else
 	return make_list(ret2, subdirs);
}

		

function list_supicious_files(share)
{
 local_var dirs;
 num_suspects = 0;

 r = NetUseAdd(login:login, password:pass, share:share);
 if ( r != 1 ) return NULL;
 suspect = NULL;

 dirs = get_dirs(basedir:NULL, level:0);
 if ( ! isnull(dirs) ) foreach dir (dirs)
 {
  Ldir = tolower(dir);
  if("clock.avi" >!< Ldir && "\winamp\demo.mp3" != Ldir &&
     !ereg(pattern:"^MVI_", string:dir, icase:TRUE) && ereg(pattern:".*\.(mp3|mpg|mpeg|ogg|avi|wma)$", string:dir, icase:TRUE))
   {
    if(isnull(suspect)) suspect = make_list(dir);
    else suspect = make_list(suspect, dir);
    num_suspects ++;
    if (num_suspects >= 40 )
    {
     suspect = make_list(suspect, "... (more) ...");
     return suspect;
    }
   }
 } 
 NetUseDel(close:FALSE);
 
 return(suspect);
}		


#
# Here we go
#		


name = kb_smb_name();
login = kb_smb_login();
pass =  kb_smb_password();
dom = kb_smb_domain();

if(!get_port_state(port))exit(1);
shares = get_kb_list("SMB/shares");

if(isnull(shares))exit(0);
else shares = make_list(shares);

soc = open_sock_tcp(port);
if (!soc)
  exit (0);

session_init(socket:soc, hostname:name);

report = NULL;
foreach share (shares) 
{
  if ( share != "ADMIN$" )
  {
  files = list_supicious_files(share:share);
  if(!isnull(files))
  {
   report += " + " + share + ' :\n\n';
   foreach f (files)
   {
    report += '  - ' + f + '\n';
   }
   report += '\n\n';
  }
 }
}

NetUseDel();

if(report != NULL)
 {
  report = "
Here is a list of files which have been found on the remote SMB shares.
Some of these files may contain copyrighted materials, such as commercial
movies or music files. 

If any of this file actually contains copyrighted material and if
they are freely swapped around, your organization might be held liable
for copyright infringement by associations such as the RIAA or the MPAA.

" + report + "

Solution : Delete all the copyrighted files";

  security_warning(port:port, data:report);
 }

