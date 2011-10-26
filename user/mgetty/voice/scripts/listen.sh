#/bin/sh
#
# From: ELBERS@bng.nl (H.D. Elbers)
# Date: Thu, 12 Dec 1996 12:16:46 +0100 (MET)
# Cc: helbers@solair1.inter.NL.net (H.D. Elbers)
#
# Hello Marc,
#
# Since it wasn't possible to play the recorded messages from my Elsa modem
# on my soundblaster with the pvftools used in the "listen" script I hacked it
# a bit to use an external microphone which is connected to the soundblaster.
# I also externded the script with a "played" directory containing compressed
# already played messages.
# Perhaps you can use it for the next vgetty-distribution?
#
# Greetings, Henk.
#
VOICEDIR=/usr/spool/voice/incoming
VM="vm play -s"
MIXER=~/sound/sndkit/mixer
DIALOG=dialog
FLAG=.flag
FILES=va*.rmd
ZFILES=va*.rmd.gz

play_msg()
{
    $DIALOG </dev/tty --title "PLAYING FILE" --infobox \
     "Playing $choice\npress [space] to skip" 5 51
    trap "" SIGINT
    stty quit ' '
    $MIXER vol 100 > /dev/null 2>&1
    $MIXER mic 100 > /dev/null 2>&1
    rm -f /var/lock/LCK..ttyS1
    $VM $choice
    echo $$ > /var/lock/LCK..ttyS1
    $MIXER mic 0   > /dev/null 2>&1
    $MIXER vol 80  > /dev/null 2>&1
    stty sane
    trap SIGINT
}

if [ -f /var/lock/LCK..ttyS1 ]
then
    echo "modem is locked..."
    exit 1
fi
echo $$ > /var/lock/LCK..ttyS1
cd $VOICEDIR
DONE=no
while [ $DONE = "no" ]
do
    if $DIALOG </dev/tty --clear --title "PLAY VOICE" \
     --menu "Pick a voice file to play" 20 51 14 \
     `ls -lt $FILES 2>/dev/null \
     | awk '{ printf("%s %s-%s-%s-(%dk)\n",$9,$6,$7,$8,$5/1024) }'` \
     played 'already played messages' 2> /tmp/menu.tmp.$$;\
    then
     choice=`cat /tmp/menu.tmp.$$`
     if [ $choice = "played" ]
     then
         cd $VOICEDIR/played
         P_DONE=no
         while [ $P_DONE = "no" ]
         do
          if $DIALOG </dev/tty --clear --title "PLAY VOICE" \
              --menu "Pick a voice file to play" 20 51 14 \
              `ls -lt $ZFILES 2>/dev/null | awk \
              '{ printf("%s %s-%s-%s-(%dk)\n",$9,$6,$7,$8,$5/1024) }'` \
              2> /tmp/menu.tmp.$$;
          then
              choice=`cat /tmp/menu.tmp.$$`
              gunzip < $choice > /tmp/menu.rmd.$$
              choice=/tmp/menu.rmd.$$
              play_msg
              rm $choice
          else
              P_DONE=yes
          fi
         done
         cd $VOICEDIR
     else
         play_msg
         if $DIALOG </dev/tty --clear --title "DELETE FILE" \
              --menu $choice 10 60 3 \
              1 "keep message" \
              2 "move message to $VOICEDIR/played" \
              3 "delete message" 2> /tmp/menu.tmp.$$
         then
          ans=`cat /tmp/menu.tmp.$$`
          if [ $ans -eq 2 ];then mv $choice played;gzip played/$choice;fi
          if [ $ans -eq 3 ];then rm $choice;fi
         fi
     fi
    else
     $DIALOG --clear
     DONE=yes
     rm -f $FLAG
    fi
    rm -f /tmp/menu.tmp.$$
done
rm -f /var/lock/LCK..ttyS1
