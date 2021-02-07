# ARP Spoofer
```
	   _____ ____________________    _________                     _____             
	  /  _  \\______   \______   \  /   _____/_____   ____   _____/ ____\___________ 
	 /  /_\  \|       _/|     ___/  \_____  \\____ \ /  _ \ /  _ \   __\/ __ \_  __ \
	/    |    \    |   \|    |      /        \  |_> >  <_> |  <_> )  | \  ___/|  | \/
	\____|__  /____|_  /|____|     /_______  /   __/ \____/ \____/|__|  \___  >__|   
	        \/       \/                    \/|__|                           \/       


			    |---::[ ARP Spoofer ]::---|


|+ USAGE:

	[i] Spoof targets and hosts ARP tables:

		./arp_spoofer.py -t <target> -o <host> [-f <ip_forwarding|binary_yes_no>]


|+ PARAMETERS:

	-h, --help
		Show this help.

	-t, --target= ["192.168.0.46"]
		Specify target IP address.

	-o, --host= ["192.168.0.1"]
		Provide gateway IP address.

	-f, --ipforward= ["yes|no"] | Default: yes
		[Optional]: Turn OFF/ON IP forwarding.



```

## Installation & Usage

Clone the repository:

```git clone https://github.com/hybero/arp-spoofer.git```

Cd into the directory:

```cd arp-spoofer/```

Install required libraries:

```pip3 install -r requirements.txt```

Run the script to send ARP spoofed packets:

```./arp_spoofer.py -t 192.168.0.46 -o 192.168.0.1 -f yes```

Script spoofs targets and gateways op-at packets, manipulating targets and gateways ARP tables. Quit spoofing by pressing 'CTRL+C'.
