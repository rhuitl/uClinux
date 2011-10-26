Newsgroups: de.comp.os.linux
Path: greenie!marvin.muc.de!ftp.space.net!stasys!sungy!brinkley.East.Sun.COM!newsworthy.West.Sun.COM!koriel!ames!nntp-server.caltech.edu!vixen.cso.uiuc.edu!howland.reston.ans.net!EU.net!Germany.EU.net!pophh!nordwest.germany.eu.net!uniol!caty.ol.sub.de!shlink.shn.com!wuff.sane.de!wuemaus!fritz
From: fritz@wuemaus.franken.de (Fritz Elfert)
Subject: Re: ghostscript und die Umlaute
Message-ID: <1994Oct6.212441.1610@wuemaus.franken.de>
Organization: Kommunikationsnetz Franken e.V.
Date: Thu, 6 Oct 1994 21:24:41 GMT
References: <CwxxB5.Dtx@hermes.hrz.uni-bielefeld.de> <CwyAAB.512@greenie.muc.de> <Cx0K48.s6@elbereth.thur.de> <Cx7Bst.AH4@lotte.sax.de>
X-Newsreader: TIN [version 1.2 PL2]
Lines: 117

Heiko Schlittermann (heiko@lotte.sax.de) wrote:
: Die urspr"ungliche Frage ging ja von a2ps aus.  Dem fehlte wirklich
: nur der Schalter -8 (RTFMOM - RTFM once more.  Vor langer Zeit
: gelesen, aber damals keine Umlaute gebraucht...)   Das schreibt dann
: an diverse Stellen ein ISO*Encoding ins PostScript-Dokument und
: das sz z.B. als \337  (wirklich 3 Zeichen).
[....]
: Soweit so gut.  Aber wenn ich nun hergehe, und gslp nutzt, um den das
: sz enthaltenen Text in Postscript zu wandeln, fehlen die Umlaute
: einfach (fehlen nicht ganz, Leerzeichen sind an ihrer Stelle.)

: Ob da einfach nur einer fehlt, der von PostScript 'ne Ahnung hat und
: gslp.ps "andert?
Gut, überredet ;-) ich hab's mal eben in den gslp eingebaut. Hier ist
ein context-diff vom gslp der GhostScript-3.0-Distribution auf mein
neues gslpiso.ps Die Reencode-routine hab ich etwas modifiziert, denn
das Original hat einfach den ISO-encodeten-Font über den normalen
Font drübergebraten (nicht ganz die feine Englische...) bei mir wird
jeweils ein neuer Font mit "ISO-" vornedran erzeugt:
==========================================================================
*** gslp.ps	Thu Jul 28 02:40:00 1994
--- gslpiso.ps	Thu Oct  6 22:09:03 1994
***************
*** 45,53 ****
  lpdict begin
  
  % Define the initial values of the printing parameters.
  
  /BodyFont null def		% use default
    /defaultBodyFont
!     { /Courier findfont Landscape { 7 } { 10 } ifelse scalefont } def
  /Columns 1 def
  /DetectFileType false def
--- 45,63 ----
  lpdict begin
  
+ % Iso-Latin1-Encoding
+ /ISOfindfont {
+   dup 100 string cvs (ISO-) exch concatstrings cvn exch
+   findfont dup maxlength dict begin
+     {1 index/FID ne{def}{pop pop}ifelse}forall
+     /Encoding ISOLatin1Encoding def
+     currentdict
+   end definefont
+ } def
+ 
  % Define the initial values of the printing parameters.
  
  /BodyFont null def		% use default
    /defaultBodyFont
!     { /Courier ISOfindfont Landscape { 7 } { 10 } ifelse scalefont } def
  /Columns 1 def
  /DetectFileType false def
***************
*** 62,66 ****
  /HeadingFont null def		% use default
    /defaultHeadingFont
!     { /Courier-Bold findfont 10 scalefont } def
  /Landscape false def
  /MarginBottom 36 def		% 1/2"
--- 72,76 ----
  /HeadingFont null def		% use default
    /defaultHeadingFont
!     { /Courier-Bold ISOfindfont 10 scalefont } def
  /Landscape false def
  /MarginBottom 36 def		% 1/2"
***************
*** 164,168 ****
   { OutFile null ne
      { exch wosp
!       dup /FontName get wosp OutFile ( findfont) writestring
        /FontMatrix get 0 get 1000 mul round cvi wosp
        OutFile ( scalefont def\n) writestring
--- 174,178 ----
   { OutFile null ne
      { exch wosp
!       dup /FontName get wosp OutFile ( ISOfindfont) writestring
        /FontMatrix get 0 get 1000 mul round cvi wosp
        OutFile ( scalefont def\n) writestring
***************
*** 329,333 ****
        1 sub
      } loop
!    arg exch 0 exch getinterval dup cvn findfont
     exch arg exch anchorsearch pop pop cvr scalefont
   } def
--- 339,343 ----
        1 sub
      } loop
!    arg exch 0 exch getinterval dup cvn ISOfindfont
     exch arg exch anchorsearch pop pop cvr scalefont
   } def
***************
*** 406,410 ****
  /-n { pop } def		% ignore
  /-o { more } def	% ignore
! /-p { (w) file /OutFile exch def   OutFile (%!\n) writestring } def
  /-P { pop } def		% ignore
  /-q { /Noisy false def   more } def
--- 416,422 ----
  /-n { pop } def		% ignore
  /-o { more } def	% ignore
! /-p { (w) file /OutFile exch def   OutFile (%!\n) writestring 
!   /ISOfindfont dup wosp load wosp OutFile (def) writestring
! } def
  /-P { pop } def		% ignore
  /-q { /Noisy false def   more } def
==========================================================================

Ciao
 -Fritz
--
Fritz Elfert 
Wuerzburg/Germany                           email: fritz@wuemaus.franken.de
---------------------------------------------------------------------------
Einen Brief mit der Deutschen Bundespost verschicken heisst ihn aufzugeben.

