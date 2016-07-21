# mailScan

Scope: 
A script to analyze spam mails from multiple ips on the same subnet and block them with iptables.

History:
I have a very old email and lately the amount of spam reached my breaking point with over 500 spam mails per day.

So I analyzed the maillog and found hundreds of emails addressed to me coming from about every server on a given C-net.
The problem is these mails are coming from a Botnet with thousands of ips and are addressed to my email, very likely to millions of other email accounts around the world too. Blacklisting on the server only get rid of the most aggressive ones. This trickle of spam from thousands of ips is not in any Blacklist. 
For a couple of weeks I blocked manually and had limited success reducing the spam, but even that got too tedious.
Automate!
Bash and PHP to the task...
This is running on centos and needs probably minor adjustments to run on other OS.

I hope this is getting rid of spam for every sysadmin on the Internets 

Bernhard Pfennigschmidt
CIO Cancun Online

