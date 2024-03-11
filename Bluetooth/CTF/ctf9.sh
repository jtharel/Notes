for X in `cat count.txt` ; do
	gatttool -b  30:AE:A4:7D:69:BE --char-write-req -a 0x003c -n $X
done;

