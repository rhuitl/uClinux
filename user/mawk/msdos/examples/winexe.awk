# Ben Myers <0003571400@mcimail.com>

# Sum up segment sizes of all Windows EXEs in current directory
# requires DOS 5.0 and Borland TDUMP
# run with
#       awk -fwinexe.awk work1
# where work1 is a work file
# You must have at least one filename as an arg, else awk will want to read
# from con:, hence the requirement for work1
BEGIN {
# redirection done by shelled command
system("del workfile.$%$") # Will probably cause a File Not Found message
# Generate a list of EXEs
system("dir *.exe /b > workfile.$%$")
while (getline < "workfile.$%$" > 0) {
# TDUMP keeps on piping to the workfile
system("tdump " $1 ">> " ARGV[1])
}
module_name = "" # initialize
# Now read workfile back, processing lines that:
# 1. contain EXE file name
# 2. contain segment type
# Print EXE name and stats for each segment type processed
# When there is a new EXE name, print summary for EXE just processed
j = 1
while (getline < ARGV[1] > 0) {
# module name
if($1 == "Display" && $2 == "of" && $3 == "File") {
# Print program summary for all but last program
if(module_name != "") { Print_Summary() }
otcount = 0 # text segment counter
odcount = 0 # data segment counter
otsize = 0  # text size accumulator
odsize = 0  # data size accumulator
module_name = $4 }
# File Size
if($1 == "DOS" && $2 == "File" && $3 == "Size") {
# 6+ digit file size with leading left paren
DOS_Size = substr($5,2,7)
# file size < 6 digits
if(DOS_Size == 0 || DOS_Size == "") { DOS_Size = $6 }
}
# CODE segment
if($1 == "Segment" && $2 == "Type:" && $3 =="CODE") {
decval = hexdec(substr($7,1,4))
otsize += decval
# printf ("%12s CODE %4s %7u\n", module_name, $7, decval)
otcount++ }
# DATA segment
if($1 == "Segment" && $2 == "Type:" && $3 =="DATA") {
decval = hexdec(substr($7,1,4))
odsize += decval
# printf ("%12s DATA %4s %7u\n", module_name, $7, decval)
odcount++ }
} # while
} # end of BEGIN section
# no main loop at all!
END {
# print record for last program
Print_Summary()
# delete work files
system("del "ARGV[1])
system("del workfile.$%$")
}  # end of END section

# No scanf in awk, so convert hex string x to decimal the hard way
function hexdec (x) {
result = 0
for (i=1; i<=length(x); i++) {
thechar = substr(x,i,1)
# digits 0-9 and lower case hex produced by TDUMP
# use brute force
if (thechar == "0") {result = result*16}
if (thechar == "1") {result = result*16 + 1}
if (thechar == "2") {result = result*16 + 2}
if (thechar == "3") {result = result*16 + 3}
if (thechar == "4") {result = result*16 + 4}
if (thechar == "5") {result = result*16 + 5}
if (thechar == "6") {result = result*16 + 6}
if (thechar == "7") {result = result*16 + 7}
if (thechar == "8") {result = result*16 + 8}
if (thechar == "9") {result = result*16 + 9}
if (thechar == "a") {result = result*16 + 10}
if (thechar == "b") {result = result*16 + 11}
if (thechar == "c") {result = result*16 + 12}
if (thechar == "d") {result = result*16 + 13}
if (thechar == "e") {result = result*16 + 14}
if (thechar == "f") {result = result*16 + 15}
if (thechar == "A") {result = result*16 + 10}
if (thechar == "B") {result = result*16 + 11}
if (thechar == "C") {result = result*16 + 12}
if (thechar == "D") {result = result*16 + 13}
if (thechar == "E") {result = result*16 + 14}
if (thechar == "F") {result = result*16 + 15}
} # for (i=1;i<length(x);i++)
return result
} # function hexdec (x)

function Print_Summary () {
# zero segment counts mean non-Windows EXE, so don't print
if (otcount+otcount != 0) {
printf ("%12s - %10.0f bytes\n", module_name, DOS_Size)
printf ("%5.0f TEXT segments with %10.0f bytes\n", otcount, otsize)
printf ("%5.0f DATA segments with %10.0f bytes\n", odcount, odsize)
}
}
