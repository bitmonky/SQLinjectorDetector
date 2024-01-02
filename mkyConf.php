<?php
$MKYC_dbconf = "/yourpath/db.conf";  // something out side of your websrv root!
try {
  $myfile = fopen($MKYC_dbconf, "r");  //or die("WTF-Database Config Not Available!");
}
catch (Exception $e) {
  echo $e;
}
$conf = fread($myfile,filesize($MKYC_dbconf));
fclose($myfile);

$SQL_ICDirectSQL = 0;
$db = json_decode($conf);

$db1 = $db->dbservers[$SQL_ICDirectSQL];
?>
