if [ -z $1 ]
	then 
		echo "Usage: "
		echo "  ./Read_all_handles.sh <Bluetooth Hardware Address>"
		echo "  "
		echo "  ./Read_all_handles.sh 00:01:02:03:04:05"
	else
		IFS=$'\n'
		for X in `gatttool -b $1 --char-desc |cut -d ' ' -f 3 |cut -d , -f 1` ; do 
			echo "Handle: " $X >> handles.txt
			for Z in `gatttool -b $1 --char-read -a $X |cut -d ':' -f 2` ; do
				echo "Characteristic value\/descriptor: " $Z >> handles.txt
				echo $Z |xxd -r -p >> handles.txt
			done;
			echo ' ' >> handles.txt
			echo "------------------------- " >> handles.txt
		done;
fi

