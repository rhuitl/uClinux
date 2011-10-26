From:    "Cory F. Cohen" <syscory@starbase.spd.louisville.edu>
To:      spaf
Subject: Tripwire holes in HPUX...
Date:    Fri, 04 Mar 94 10:27:22 -0500

I have a feature fix for tripwire....

In HPUX there are these dandy little files called context dependent
files.  They're used for HP-UX clustering, and they leave GREAT BIG
holes in programs like tripwire. (and everything else :-( )

--- very short descritpion of CDF's (context dependent files) ----------
They were created for supporting multiple binary architectures in one
cluster.  HPUX processes have something called a context to determine
which file to run.  Oh hell, take a look at the script output I sent
if you're not familiar with them...
------------------------------------------------------------------------

Anyway, I've summarized my changes to config.parse.c below, sent you
a complete config.parse.c, and some script output demonstrating
CDF's and how they really screw-up tripwire.

I make no commitments as to the accuracy of this code. Two bugs: (?)
 1) strcat(MAXPATHLEN, "+") into a MAXPATHLEN array
    I'm not sure how HP deals with this.
 2) CDF's still get screwed up if someone creates a file ending with "+"
    (But even HP's got this part screwed up... :-) )

------- Message 3

From:    "Cory F. Cohen" <syscory@starbase.spd.louisville.edu>
To:      spaf
Subject: HPUX CDF Script
Date:    Fri, 04 Mar 94 10:31:45 -0500

This is the best way I know to describe the little buggers.

Script started on Fri Mar  4 09:52:56 1994
#
# A little setup...
#
bash# mkdir example
bash# cd example
bash# ls -Fla
total 8
drwx------   2 root     sys           24 Mar  4 09:53 ./
drwx------   7 root     sys         1024 Mar  4 09:53 ../
bash# mkdir a
bash# echo >a/a1
bash# echo >a/a2
bash# ls -Fla
total 12
drwx------   3 root     sys         1024 Mar  4 09:53 ./
drwx------   7 root     sys         1024 Mar  4 09:53 ../
drwx------   2 root     sys         1024 Mar  4 09:53 a/
bash# ls -Fla a
total 16
drwx------   2 root     sys         1024 Mar  4 09:53 ./
drwx------   3 root     sys         1024 Mar  4 09:53 ../
-rw-------   1 root     sys            1 Mar  4 09:53 a1
-rw-------   1 root     sys            1 Mar  4 09:53 a2
bash# mkdir h
bash# echo >h/h1
bash# echo >h/h2
bash# ls -Fla
total 16
drwx------   4 root     sys         1024 Mar  4 09:53 ./
drwx------   7 root     sys         1024 Mar  4 09:53 ../
drwx------   2 root     sys         1024 Mar  4 09:53 a/
drwx------   2 root     sys         1024 Mar  4 09:53 h/
bash# ls -Fla h
total 16
drwx------   2 root     sys         1024 Mar  4 09:53 ./
drwx------   4 root     sys         1024 Mar  4 09:53 ../
-rw-------   1 root     sys            1 Mar  4 09:53 h1
-rw-------   1 root     sys            1 Mar  4 09:53 h2
#
# Here's where the fun stuff starts...
#
bash# chmod +H h
#
# h is now a hidden directory (a context dependent file (CDF))
#
bash# ls -Fla
total 12
drwx------   4 root     sys         1024 Mar  4 09:53 ./
drwx------   7 root     sys         1024 Mar  4 09:53 ../
drwx------   2 root     sys         1024 Mar  4 09:53 a/
#
# Hey! Where did it go?
#
bash# ls -Fla h
h not found
bash# ls -FlaH
total 16
drwx------   4 root     sys         1024 Mar  4 09:53 ./
drwx------   7 root     sys         1024 Mar  4 09:53 ../
drwx------   2 root     sys         1024 Mar  4 09:53 a/
Hrws------   2 root     sys         1024 Mar  4 09:53 h+
#
# Oh there it is, with a plus after it and a suid bit!
#
bash# ls -Fla h+
total 16
drws------   2 root     sys         1024 Mar  4 09:53 ./
drwx------   4 root     sys         1024 Mar  4 09:53 ../
-rw-------   1 root     sys            1 Mar  4 09:53 h1
-rw-------   1 root     sys            1 Mar  4 09:53 h2
#
# Here's what it's really for...
#
bash# hostname
starbase
bash# echo >h+/starbase "Isn't this nifty"
bash# ls -Fla
total 16
drwx------   4 root     sys         1024 Mar  4 09:53 ./
drwx------   7 root     sys         1024 Mar  4 09:53 ../
drwx------   2 root     sys         1024 Mar  4 09:53 a/
-rw-------   1 root     sys           17 Mar  4 09:54 h
#
# Plain old h is back...
#
bash# cat h
Isn't this nifty
#
# but h+ is still there too.
#
bash# ls -Fla h+
total 20
drws------   2 root     sys         1024 Mar  4 09:54 ./
drwx------   4 root     sys         1024 Mar  4 09:53 ../
-rw-------   1 root     sys            1 Mar  4 09:53 h1
-rw-------   1 root     sys            1 Mar  4 09:53 h2
-rw-------   1 root     sys           17 Mar  4 09:54 starbase
#
# It'll match any of the words in this list...
#
bash# getcontext
starbase PA-RISC1.1 HP-PA localroot default
#
# Let's try an architecture dependent one...
#
bash# echo >h+/HP-PA "This is for all HP-PA hosts"
#
# h is still there...
#
bash# ls -Fla
total 16
drwx------   4 root     sys         1024 Mar  4 09:53 ./
drwx------   7 root     sys         1024 Mar  4 09:53 ../
drwx------   2 root     sys         1024 Mar  4 09:53 a/
-rw-------   1 root     sys           17 Mar  4 09:54 h
#
# But it's the old one.
#
bash# cat h
Isn't this nifty
#
# It matches in order...
#
bash# rm h+/starbase
bash# cat h 
This is for all HP-PA hosts
#
# Are you confused yet?
#
bash# ls -Fla 
total 16
drwx------   4 root     sys         1024 Mar  4 09:53 ./
drwx------   7 root     sys         1024 Mar  4 09:53 ../
drwx------   2 root     sys         1024 Mar  4 09:53 a/
-rw-------   1 root     sys           28 Mar  4 09:57 h
#
# I thought so :-)
#
bash# chmod 700 h+
bash# ls -Fla
total 16
drwx------   4 root     sys         1024 Mar  4 09:53 ./
drwx------   7 root     sys         1024 Mar  4 09:53 ../
drwx------   2 root     sys         1024 Mar  4 09:53 a/
drwx------   2 root     sys         1024 Mar  4 09:57 h/
#
# My code doesn't fix this... HP will have to...
#
bash# echo >h+ "HPUX hates this"
#
# h+ is a file and h is a normal directory...
#
bash# ls -Fla
total 20
drwx------   4 root     sys         1024 Mar  4 09:58 ./
drwx------   7 root     sys         1024 Mar  4 09:53 ../
drwx------   2 root     sys         1024 Mar  4 09:53 a/
drwx------   2 root     sys         1024 Mar  4 09:57 h/
-rw-------   1 root     sys           16 Mar  4 09:58 h+
#
# But not for long...
#
bash# chmod +H h
#
# Now h AND h+ are files...
#
bash# ls -FlaH
total 20
drwx------   4 root     sys         1024 Mar  4 09:58 ./
drwx------   7 root     sys         1024 Mar  4 09:53 ../
drwx------   2 root     sys         1024 Mar  4 09:53 a/
-rw-------   1 root     sys           28 Mar  4 09:57 h
-rw-------   1 root     sys           16 Mar  4 09:58 h+
#
# All files...
#
bash# ls -Fla h+
-rw-------   1 root     sys           16 Mar  4 09:58 h+
bash# ls -FlaH h+
-rw-------   1 root     sys           16 Mar  4 09:58 h+
bash# ls -Fla h
-rw-------   1 root     sys           28 Mar  4 09:57 h
#
# h/h1 and h/h2 are GONE!
#
# People could still hide stuff from tripwire this way, since
# HP can't even find the damn things...
#
# Let's remove the offfending h+ FILE.
#
bash# rm h+
bash# ls -FlaH
total 16
drwx------   4 root     sys         1024 Mar  4 09:59 ./
drwx------   7 root     sys         1024 Mar  4 09:53 ../
drwx------   2 root     sys         1024 Mar  4 09:53 a/
Hrws------   2 root     sys         1024 Mar  4 09:57 h+
#
# Didn't I just rm h+?
#
bash# ls -Fla h+
total 20
drws------   2 root     sys         1024 Mar  4 09:57 ./
drwx------   4 root     sys         1024 Mar  4 09:59 ../
-rw-------   1 root     sys           28 Mar  4 09:57 HP-PA
-rw-------   1 root     sys            1 Mar  4 09:53 h1
-rw-------   1 root     sys            1 Mar  4 09:53 h2
#
# Oh... It's the directory again... And are files are back!
#
# Just think. I have these CUTE little things ALL OVER
# my system.  /tmp, /etc, /dev, /bin, everywhere..
# I think it's a miracle that people haven't helped
# themselves to all my disk space...
#
# Hope that helps...
#
bash# exit
script done on Fri Mar  4 09:59:43 1994

Hope this helped if you're not familiar with CDF's.  Most people
I've met running HPUX don't even know they exist unless they run
in a clustered environment like I do.

Cory
--
======================================================================
Cory Forrest Cohen                        
University of Louisville
syscory@starbase.spd.louisville.edu
======================================================================

------- End of Forwarded Messages


