for X in {0..1000..1} 
do
	gatttool -b 30:AE:A4:7D:69:BE --char-read -a 0x003e	
done

