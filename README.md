# mailScan.php

Scope: 
A script to analyze spam mails from multiple ips on the same subnet and block them with iptables.

History:
I have a very old email and lately the amount of spam reached my breaking point with over 500 spam mails per day.
So I analyzed the maillog and found hundreds of emails addressed to me coming from about every server on a given C-net.

The problem is these e-mails are coming from a Botnet with thousands of ips and are correctly addressed to my email, very likely to millions of email accounts around the world. Blacklisting on the server only get rid of the most aggressive ones. This trickle of spam from thousands of ips flies under the Radar and is not in any Blacklist. 

For a couple of weeks I blocked manually and had limited success reducing the spam, but even that got too tedious.

Solution:

Automate! Bash and PHP to the task...

This is running on centos and needs probably minor adjustments to run on other OS.

I hope this script is helping every sysadmin on the Internets getting rid of a lot of spam.

Bernhard Pfennigschmidt
CIO Cancun Online

