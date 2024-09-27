build:
	g++ dhcp-stats.cpp -o dhcp-stats -lpcap -lncurses
clean:
	rm dhcp-stats
