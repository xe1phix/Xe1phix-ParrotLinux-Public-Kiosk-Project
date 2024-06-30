ipset create ip_whitelist hash:ip
	
iptables --table nat --new prerouting_mychain
iptables --table nat --insert PREROUTING -j prerouting_mychain
iptables --table nat --append prerouting_mychain --match set --match-set ip_whitelist src -j RETURN
iptables --table nat --append prerouting_mychain --dport 80 -j DNAT --to-destination <internal http server>
	
iptables --table filter --new forward_mychain
iptables --table filter --insert FORWARD -j forward_mychain
iptables --table filter --insert forward_mychain -j DROP (this ends up being the last rule)
iptables --table filter --insert forward_mychain --match set --match-set ip_whitelist src -j ACCEPT
	
iptables --table filter --insert forward_mychain -p udp --dport 53 -j ACCEPT
iptables --table filter --insert forward_mychain -p udp --sport 53 -j ACCEPT
	
ipset add ip_whitelist 10.10.10.10
	
ipset del ip_whitelist 10.10.10.10
	
CREATE DATABASE Testdb; 
CREATE TABLE `Clients` (   
`IP` varchar(15) DEFAULT NULL,   
`Created` datetime DEFAULT NULL,   
`Expiry` datetime DEFAULT NULL,   
`LastAccess` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,   UNIQUE KEY `ipidx` (`IP`) 
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
	
<!DOCTYPE html >
<html>
   <head>
       <title></title>
   </head>
   <body>
       <?php
       $ClientIPAddr = filter_var($_SERVER["REMOTE_ADDR"], FILTER_VALIDATE_IP);
       $sqlQuery = "";
       if (($ClientIPAddr === FALSE) || ($ClientIPAddr === NULL)) {
           echo "Failed to obtain client IP [" . $_SERVER["REMOTE_ADDR"] . "]";
           exit;
       }
	
$mysqli = new mysqli("<database ip>", "dbuser", "dbpass", "Testdb");
       if ($mysqli->connect_errno) {
           echo "Failed to connect to MySQL: " . $mysqli->connect_error;
           exit;
       } else {
           echo "Connected (" . $mysqli->server_info . ")<br />";
       }
       echo "Now for a query on " . $ClientIPAddr . ":<br />";
       // Check to see if IP is in database and has not expired
       $sqlQuery = "SELECT IP, TIMEDIFF(Expiry, now()) from Clients where IP="" . $ClientIPAddr . "";";
       if (($result = $mysqli->query($sqlQuery)) === FALSE) {
           echo "Query Error (" . $mysqli->error . ") on (" . $sqlQuery . ")<br />";
           exit;
       } else {
           echo "<h2>Query Result(" . $result->num_rows . "):</h2>";
           echo "<table>";
           while (($row = $result->fetch_array(MYSQLI_NUM)) !== NULL) {
               echo "<tr>";
               foreach ($row as $value) {
                   echo "<td>" . $value . "</td>";
               }
               echo "</tr>";
           }
           echo "</table>";
           echo "<h1>Welcome to my Test Page</h1>";
           if ($result->num_rows === 0) {
               echo "<p>New(" . $result->num_rows . "): " . $ClientIPAddr . "</p>";
               echo "<p>You now have full Internet access.</p>";
           } else {
               echo "<p>Returning(" . $result->num_rows . "): " . $ClientIPAddr . "</p>";
               echo "<p>Your Internet access has been extended.</p>";
           }
           $result->free();
           $sqlQuery = "INSERT INTO Clients (IP, Created, Expiry) VALUES ("" . $ClientIPAddr . "", now(),
               timestampadd(hour, 24, now())) ON DUPLICATE KEY UPDATE Expiry=timestampadd(hour, 24, now());";
           if (($result = $mysqli->query($sqlQuery)) === FALSE) {
               echo "Query Error (" . $mysqli->error . ") on (" . $sqlQuery . ")<br />";
               exit;
           } else {
	
// **************** UPDATE IPSET *****************
               //ssh2_connect, ssh2_fingerprint, ssh2_auth_pubkey_file, ssh2_auth_password, ssh2_exec
               if (($sshConnect = ssh2_connect("<GW IP>")) === FALSE) {
                   $err = error_get_last();
                   echo $err["message"];
                   exit;
               }
               if (ssh2_auth_pubkey_file($sshConnect, "root", "/usr/share/nginx/rsa.pub", "/usr/share/nginx/rsa") === FALSE) {
                   $err = error_get_last();
                   echo $err["message"];
                   exit;
               }
               if (($stream = ssh2_exec($sshConnect, "ipset add ip_whitelist " . $ClientIPAddr)) === FALSE) {
                   $err = error_get_last();
                   echo $err["message"];
                   exit;
               }
               $stderr_stream = ssh2_fetch_stream($stream, SSH2_STREAM_STDERR);
               if ((stream_set_blocking($stream, true) === FALSE) ||
                       (stream_set_blocking($stderr_stream, true) === FALSE)) {
                   $err = error_get_last();
                   echo $err["message"];
                   exit;
               }
               if (($resultStr = stream_get_contents($stream)) === FALSE) {
                   $err = error_get_last();
                   echo $err["message"];
                   exit;
               }
               if ($resultStr === "") { // Likely an error
                   if (($resultStr = stream_get_contents($stderr_stream)) === FALSE) {
                       $err = error_get_last();
                       echo $err["message"];
                       exit;
                   }
               }
               echo "<pre>" . $resultStr . "</pre>";
           }
       }
       $mysqli->close();
       ?>
   </body>
</html>
