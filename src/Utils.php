<?php
namespace SWServices\DescMass;
use Exception;

class Utils {
  public static function headers($xmlString, $soapAction, $token){
    return  array(
                 "Content-type: text/xml;charset=\"utf-8\"",
                 "Accept: text/xml",
                 "Cache-Control: no-cache",
                 $token ? "Authorization: WRAP access_token=\"".$token."\"":"",
                 "SOAPAction: ".$soapAction, 
                 "Content-length: ".strlen($xmlString),
             );
  }
  public static function xmlToArray($xml){
    return json_decode(json_encode(simplexml_load_string(str_replace("s:", "", str_replace("o:","", str_replace("u:","",str_replace("h:","",'<?xml version="1.0" encoding="utf-8"?>'.$xml)))))),TRUE);
  }

  public static function genUuid() {
    return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),
        mt_rand( 0, 0xffff ),
        mt_rand( 0, 0x0fff ) | 0x4000,
        mt_rand( 0, 0x3fff ) | 0x8000,
        mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
    );
  }

  public static function derToPem($der_data, $type='CERTIFICATE') {
    $pem = chunk_split(base64_encode($der_data), 64, "\n");
    $pem = "-----BEGIN ".$type."-----\n".$pem."-----END ".$type."-----\n";
    return $pem;
 }

 public static function saveBase64File($data, $filename){
  $data = base64_decode($data);
  file_put_contents($filename, $data);
}

}
?>