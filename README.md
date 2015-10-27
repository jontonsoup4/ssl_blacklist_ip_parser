# What is SSL Blacklist?
SSL Blacklist is a project by abuse.ch, a Swiss security company, who tracks and shares security information. abuse.ch associates the SSL certificates with malware and bonnet activities.

#How does this work?
ip_parser.py looks in a specified folder for all csv files. It then runs each csv through the parser and creates a new txt document which is more human readable because of the organization and sorted methods.

#Running
From a terminal, navigate to the folder containing the csv files and run ip_parser.py from there.


	sslipblacklist.csv is an example csv for input
	sslipblacklist.txt is an example txt of the output
