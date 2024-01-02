<?php
/*
Usage:
use checkLogInject($inputData)
  the function checks all user inputs for signs of a SQL inject attack.
  will check the input against a known database of injections scripts and some AI to test for 
  an ongoing sql inject attack.
*/
 
include_once("mkyConSqli.php");
//ini_set('display_errors', 1);
//error_reporting(E_ALL);

 
$SQL = 'Select * from tblStrangeStuf limit 1';
$res = mkyMyqry($SQL);
$rec = mkyMyFetch($res);

echo "hello World: ".$rec['stsMd5'];

function exitLogInject($data,$fld){
  global $userID;
  global $userName;
  $cln = getCleanSData($data);
  $IP = safeSRV('REMOTE_ADDR');
  $SC = safeSRV('SCRIPT_NAME');
  $m  = '<h3>Alert Sent: </h3>';
  $m .= 'IP: '.$IP;
  $m .= '<br/>USER: '.$userID.' '.$userName;
  $m .= '<br/>Script: '.$SC;
  $m .= '<br/>Field: '.$fld;
  $m .= '<br/>Data: '.$cln;
  echo $m;

  $SQL = "select count(*) nIP from tblAttIPs  where attIP = '".$IP."'";
  $result = mkyMsqry($SQL);
  $tRec = mkyMsFetch($result);

  if ($tRec['nIP'] == 0){
    $SQL = "Insert into tblAttIPs (attIP,nAtts,attLasthit) values('".$IP."',1,now())";
    $result = mkyMsqry($SQL);
    mailAdmin('peter@bitmonky.com', 'SQL Inject Alert:',$m);
  }
  else {
    $SQL = "Update tblAttIPs set nAtts = nAtts + 1,attLasthit = now() where attIP = '".$IP."'";
    $result = mkyMsqry($SQL);
  }

  $md5  = getCleanMd5($data);

  $SQL = "select count(*) nRec from tblStrangeStuf where stsMd5='".$md5."'";
  $result = mkyMsqry($SQL);
  $tRec = mkyMsFetch($result);
  if ($tRec){
    if ($tRec['nRec'] == 0){
      $stsLook = sqliQuickCheck($cln);
      if (!$stsLook){$stsLook = 'null';}
      $SQL = "insert into tblStrangeStuf (stsMd5,stsClean,stsLook) ";
      $SQL .= "values ('".$md5."','".$cln."',".$stsLook.")";
      $result = mkyMsqry($SQL);
    }
  }
  exit('<p/>done');
}
function sqliQuickCheck($inj){
  if (mkyStrpos($inj,"CAST(CHR(") !== false){
    return 1;
  }
  if (mkyStrpos($inj,"UNION") !== false){
    return 1;
  }
  if (mkyStrpos($inj,"/AND/") !== false){
    return 1;
  }
  if (mkyStrpos($inj,"/OR/") !== false){
    return 1;
  }
  if (mkyStrpos($inj,"/GROUP/") !== false){
    return 1;
  }
  if (mkyStrpos($inj,"(SELECTCONVERT(") !== false){
    return 1;
  }
  if (mkyStrpos($inj,"(SELECT") !== false){
    return 1;
  }
  if (mkyStrpos($inj,"SYSCOLUM") !== false){
    return 1;
  }
  if (mkyStrpos($inj,"ICDIRECTSQL") !== false){
    return 1;
  }
  return null;
}
function checkLogInject($data){
  //return;
  $logit = false;

  $pos = mkyStripos($data,'&#x3c');     // <
  if($pos !== false){$logit = true;}
  $pos = mkyStripos($data,'&#60');      // <
  if($pos !== false){$logit = true;}

  $pos = mkyStripos($data,'&#x27');     // '
  if($pos !== false){$logit = true;}
  $pos = mkyStripos($data,'&#39');      // '
  if($pos !== false){$logit = true;}
  $pos = mkyStripos($data,'&apos');     // '
  if($pos !== false){$logit = true;}

  $pos = mkyStripos($data,'<script');
  if($pos !== false){$logit = true;}
  $pos = mkyStripos($data,"'");
  if($pos !== false){$logit = screenFurtherText($data);}

  if ($logit){
    $cln = getCleanSData($data);
    $md5 = getCleanMd5($data);

    if (sqliQuickCheck($cln)){
      exitLogInject($data,'safeGETq');
    }
    $SQL = "select stsLook from tblStrangeStuf where stsMd5='".$md5."'";
    $result = mkyMsqry($SQL);
    $tRec = mkyMsFetch($result);

    if ($tRec){
      $look = $tRec['stsLook'];
      if ($look == 1){
        exitLogInject($data,'safeGET');
      }
    }
    else {
      $SQL = "insert into tblStrangeStuf (stsMd5,stsClean,stsLook) ";
      $SQL .= "values ('".$md5."','".$cln."',null)";
      $result = mkyMsqry($SQL);
    }
  }
}

function getCleanMd5($data){
  return md5(getCleanSData($data));
}
function getCleanSData($data){
  $cln = getSaniData($data);
  $s   = strPos($cln,'`');
  if ($s !== false){
    $cln = substr($cln,$s);
  }
  $cln = preg_replace('/\s+/', '', $cln);
  return strtoupper($cln);
}
function screenFurtherText($data){

  $pos = mkyStripos($data,"(");
  if($pos !== false){return true;}

  $pos = mkyStripos($data,"=");
  if($pos !== false){return true;}

  $pos = mkyStripos($data,"--");
  if($pos !== false){return true;}

  $pos = mkyStripos($data,"union");
  if($pos !== false){return true;}

  return false;
}
function getSaniData($str){
  global $userID;
  if ($str === null) {
    return "";
  }
  else{
     $str=mkyTrim($str);
     $str=mkyStrReplace("*",".",$str);
     $str=mkyStrReplace("--","..",$str);
     $str=mkyStrReplace(";",":",$str);
     $str=mkyStrReplace("<","",$str);
     $str=mkyStrReplace("'","`",$str);
     $str=mkyStrReplace('"','`',$str);
     $str=mkyStrReplace("}","",$str);
     $str=mkyStrReplace("{","",$str);

     $str=mkyStrReplace('&#39','',$str);
     $str=mkyStrReplace('&#34','',$str);
     $str=mkyStrReplace('&#45','',$str);
     $str=mkyStrReplace('&#60','',$str);
     $str=mkyStrReplace('&#92','',$str);
     $str=mkyStrReplace('&#35','',$str);
     $str=mkyStrReplace('&#38','',$str);
     $str=mkyStrIReplace('&lt','',$str);
     $str=mkyStrIReplace('&quot','',$str);
     $str=mkyStrIReplace('&apos','',$str);

     $str=mkyStrIReplace('&#x22','',$str); // "
     $str=mkyStrIReplace('&#x27','',$str); // '
     $str=mkyStrIReplace('&#x26','',$str); // ;
     $str=mkyStrIReplace('&#x23','',$str); // -
     $str=mkyStrIReplace('&#x2d','',$str); // #
     $str=mkyStrIReplace('&#x3b','',$str); // &
     $str=mkyStrIReplace('&#x3c','',$str); // <
     $str=mkyStrIReplace('&#x5c','',$str); // \
     $str=addslashes($str);

     return $str;
  }
}
?>
