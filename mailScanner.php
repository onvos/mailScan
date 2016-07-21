#!/usr/bin/php
<?php
	// Scope: Detection of low volume multi-ip mail spams going rampant right now

	// the good hotmail, gmail, modem and your server ips with 3 of the 4 ip number blocks.
	$cleanips = array('208.68.106','208.75.213','74.125.0','65.54.190','65.55.116','65.55.111','65.55.34','65.55.90','65.54.51','65.54.61','207.46.66','157.55.0','157.55.1','157.55.2','173.194.204','173.194.206','173.194.207','173.194.66','173.194.68','209.85.144','209.85.161','209.85.192','209.85.201','209.85.213','209.85.214','209.85.215','209.85.216','209.85.218','209.85.220','209.85.223','209.85.232','45.55.32.17','64.233.186','64.233.190','74.125.192','74.125.22','74.125.29','74.125.82');

	// get the already banned ips
	$command = "/usr/sbin/iptables -L -n | grep /24 | egrep -o '[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}' | grep -v 0.0.0.0 | sort\n";
	$code="";
	$badList0 = array();
	$badips = shell_exec($command);
   	$badList0 = explode(PHP_EOL,$badips );
        while (list ( $key, $val ) = each ( $badList0 ))
        {
		if( $val == "" ){ continue; }
		$badList[$key] = substr( $val, 0,-2 );
	}

	// get the bad ips, customize the command and filter out your own modem office website and other a b c or d net ips
	$command = '/usr/bin/cat /var/log/maillog | grep ": client=" | grep -v "187." | grep -v "189." | grep -v " 74.125." | grep -v "65.54." | grep -v "65.55." | grep -v "157.55." | grep -v 73.138.217.69 | grep -v "207.46.66." | grep -v "157.55." | grep -v NOQUEUE | egrep -o "[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}" | uniq | sort ';
	$code="";
	$newips = shell_exec( $command );
	$newList = explode( PHP_EOL,$newips );
	while (list ( $key, $val ) = each( $newList ) )
	{
		$var = explode("\t",trim( $val ));
		$digits = explode('.',trim( $var[0] ) );
		$d123 = $digits[0] . "." . $digits[1] . "." . $digits[2];
			// skip good ips if detected
			if( in_array( $d123, $cleanips ) ) { continue; }
	// count the total of mail hits per ip subnet
	$dcount[$d123]++;
	// count how many ips per subnet
 	if($oldd123 != $d123 ){ $d3units[$d123] = 1; }
	if($oldd123 == $d123 AND $olddigit3 != $digits[3] ) { $d3units[$d123]++; }
	$oldd123 = $d123;
	$olddigit3 = $digits[3];
	}

	// flush and rinse
	array_flip( $dcount );
	array_unique( $dcount );
	array_flip( $dcount );
	asort( $dcount );

	$ipcount = 0;
	while (list ( $key, $val ) = each( $dcount ) )
	{
		// skip empty ips
		if( $key == "" )
		{
			continue;
		}
		// skip already banned ips
		if( isset( $badList ) and in_array( $key, $badList ) )
		{
			continue;
		}
		// Skip subnets with less then 2 violations
		if( $d3units[ $key ] < 2 )
		{
			continue;
		}
		// 	block c nets with more then 4 violations
		if( $val > 4 )
		{
			$command = "/usr/sbin/iptables -I INPUT -s " . $key . ".0/24 -j DROP\n";
			exec( $command );
			$ipcount++;
		} // endif
	} // endwhile

	if( $ipcount > 0 )
	{
		echo "Blocked $ipcount IPs\n";
	} // endif
	echo count( $badList ) . " already blocked IPs\n";

?>
