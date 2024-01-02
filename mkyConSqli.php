<?php
include_once("mkyPHPInc.php");
include_once("mkyConf.php");
//ini_set('display_errors', 1);
//ini_set('display_startup_errors', 1);
//error_reporting(E_ALL);

$mkdb     = null;
$mkdbRead = null;
$curDbCon = null;
$erdb     = null;
mysqli_report(MYSQLI_REPORT_OFF);

function connectToBrain($read=false,$erDB=false){
   /*
     Open connectin to the mkyBrainDb to access the
     conection manager data
   */
   global $db1,$mkdb,$mkdbRead;
   if ($erDB === false){
     if ($mkdb && !$read){
       return;
     }
     if ($mkdbRead && $read){
       return;
     }
   }
   $username = $db1->user;                 //@mkySecure;
   $password = $db1->password;             //@mkySecure;
   $host     = $db1->host;                 //@mkySecure;
   $database = $db1->default;              //@mkySecure;
   $port     = $db1->port;

   $brain = mysqli_connect($host, $username, $password,$database) or die("bitMonky down for maintenance.... be back soon ");
   if (isset($GLOBALS['mkySQLLocal'])){
     mysqli_options($brain, MYSQLI_OPT_LOCAL_INFILE, 1);   
   } 
   mysqli_set_charset($brain, "utf8mb4");
   mysqli_select_db($brain,$database) or die("bitMonky down for maintenance.... be back soon");
   mysqli_set_charset($brain,'utf8mb4');
//   if (!isset($_GET['testPow'])){
//     exit("bitMonky down for maintenance.... be back soon");
//   }   
   return $brain;
}

$mkdb = connectToBrain();
$mkdbRead = connectToBrain(true);

mkyTryQry('SET SESSION TRANSACTION ISOLATION LEVEL READ UNCOMMITTED','READONLY',$mkdb);

function mkyMyqry($query,$mode=null){
   global $mkdb;
   if (!$mode){$mode = $mkdb;}
   $query = deleteFromFix($query);

   $time_pre = microtime(true);
   if ($GLOBALS['MKYC_ShowSQLTimer']){
     echo "<br/>Starting SQL Statement\n";
     echo "<br/><span style='color:blue;'>".$query."</span>\n";
   }
   $res = mkyTryQry($query,'mysql',$mode);
   $time_post = microtime(true);
   $exec_time = $time_post - $time_pre;
   if ($GLOBALS['MKYC_ShowSQLTimer']){
     echo "<br/>Job Run Time: ".$exec_time."\n";
   }

   if ($exec_time > $GLOBALS['MKYC_SQLtimer']){
     logSQL($query,"longMyQry:".$exec_time,"excToLONG");
   }
   return $res;
}
function mkyMsqry($query,$mode=null){
   global $mkdb;
   if (!$mode){$mode = $mkdb;}
   $query = topToLimit($query);
   $query = deleteFromFix($query);

   $time_pre = microtime(true);
   if ($GLOBALS['MKYC_ShowSQLTimer']){
     echo "<br/>Starting SQL Statement\n";
     echo "<br/><span style='color:blue;'>".$query."</span>\n";
   }
   $result = mkyTryQry($query,'mssql',$mode);
   $time_post = microtime(true);
   $exec_time = $time_post - $time_pre;
   if ($GLOBALS['MKYC_ShowSQLTimer']){
     echo "<br/>Job Run Time: ".$exec_time."\n";
   }

   if ($exec_time > $GLOBALS['MKYC_SQLtimer']){
     logSQL($query,"longMsQry:".$exec_time,"excToLONG");
   }
   return $result;
}
$mkySqlTrans = null;
function mkyStartTransaction(){
  if (mkyMyqry('START TRANSACTION')){
    $GLOBALS['mkySqlTrans'] = true;
  }
  return $GLOBALS['mkySqlTrans'];
}
function mkyCommit(){
  if ($GLOBALS['mkySqlTrans']){
    if (mkyMyqry('COMMIT')){
      $GLOBALS['mkySqlTrans'] = null;
      return true;
    }
  }
  return false;
}
function mkyRollback(){
  if ($GLOBALS['mkySqlTrans']){
    if (mkyMyqry('ROLLBACK')){
      $GLOBALS['mkySqlTrans'] = null;
      return true;
    }
  }
  return false;
}
function mkyMyLastID(){
  return mysqli_insert_id($GLOBALS['mkdb']);
}
function mkyMyNumRows($res){
  return mysqli_num_rows($res);
}
function mkyMsFetch($result){
   global $mkdb;
   return mysqli_fetch_array($result);
}
function mkyMyFetch($result){
   global $mkdb;
   return mysqli_fetch_array($result);
}
function setSQLMode($wl){
  global $curDbCon,$mkdb,$mkdbRead;
  $curDbCon = $mkdb;
  if (strtoupper($wl[0]) == 'SELECT'){
    $curDbCon = $mkdbRead;
  }
}
function deleteFromFix($SQL){
   //return $SQL;
   $clean = mkyTrim(preg_replace('/\s\s+/', ' ', mkyStrReplace("\n", " ", $SQL)));
   $wl = explode(" ",$clean);
   setSQLMode($wl);
   if (strtoupper($wl[0]) !== 'DELETE'){
     return $SQL;
   }
   if (strtoupper($wl[1]) == 'FROM'){
     return $SQL;
   }
   if (strtoupper($wl[2]) == 'FROM'){
     return $SQL;
   }
   return mkyStrIReplace('delete ','Delete From ',$SQL);
}
function topToLimit($SQL){
   $clean = mkyTrim(preg_replace('/\s\s+/', ' ', mkyStrReplace("\n", " ", $SQL)));
   $wl = explode(" ",$clean);
   if (strtoupper($wl[0]) !== 'SELECT'){
     return $SQL;
   }
   if (strtoupper($wl[1]) !== 'TOP'){
     return $SQL;
   }
   $limit = $wl[2];
   $mark  = mkyStrpos($SQL,$wl[3]);
   $match = left($SQL,$mark);
   $SQL = mkyStrReplace($match,'',$SQL);
   $SQL = "SELECT ".mkyTrim($SQL);
   if (substr($SQL, -1) == ";"){
     $SQL = substr_replace($SQL ,"",-1);
   }
   $SQL .= " limit ".$limit;
   return $SQL;
} 
function mkyTryQry($query,$type,$dbcon){
     $dbcon = $GLOBALS['curDbCon'];
     if ($type == 'READONLY'){
       $dbcon = $GLOBALS['mkdbRead'];
     } 
     if (!$dbcon) {exit('no database conection found');}
     $try = 0;
     while ($try < 3){
       $qres = mysqli_query($dbcon,$query);
       if ($qres === false){
         $err  = mysqli_error($dbcon);
         $erno = mysqli_errno($dbcon);
         if ($erno == 1213){
           $try = $try + 1;
           usleep(2000000);
         }
         else {
           logSQL($query,$err.":",$type);
           return $qres;
         }
       }
       else {
         return $qres;
       }
     }
     return $qres;
   }

function logSQL($sqlO,$erMsg='null',$type=null){
     //exit($erMsg."<br/>".$sqlO);
     global $erdb;
     if ($erdb === null){
       $erdb = connectToBrain($read=false,$erDB=true);
     }
     $prg = "web:".$_SERVER['SCRIPT_NAME'];
     $parm = $_SERVER['QUERY_STRING'];
     if ($erMsg !== 'null'){
       $erMsg = left("'".addslashes($erMsg)."'",1000);
     }
     $SQL = "insert into mkyBrain.conMgrLog (cmlLSql,cmlLMode,cmlLType,cmlLScript,cmlLError,cmlLSrc) ";
     $SQL .= "values ('".addslashes(left($sqlO,1000))."','".$type."','mySQL','".$prg."',".$erMsg.",'www.bitmonky')";

     $res = mysqli_query($erdb,$SQL);
/*
     if (!$res){
       exit('log Fail'.$SQL.':'.$this->brain);
       $m  = "cmd: ".left($sqlO,1000);
       $m .= "<p/>Mode: ".$this->mode;
       $m .= "<p/>Type: ".$this->dbtype;
       $m .= "<br/>Script: ".$prg;
       $m .= "<br/>Parms: ".left($parm,250);
       $m .= "<br/>Error: Insert to conMgrLog failed ->".$SQL;

       //mailAdmin('peter@bitmonky.com', 'mkyBrain Log Fail Alert:',$m);
     }
*/
     return null;
   }

?>
