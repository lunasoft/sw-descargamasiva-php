<?php
namespace SWServices\DescMass;
use Exception;

class DownloadXmlRequest{
    public static function soapRequest($cert, $keyPEM, $token, $rfc, $idPaquete){
        $xml_post_string = DownloadXmlRequest::getSoapBody($cert, $keyPEM, $rfc, $idPaquete);
        $headers = DownloadXmlRequest::headers($xml_post_string, $token);
        $ch = curl_init();
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 1);
            curl_setopt($ch, CURLOPT_URL, 'https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc');
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 0); 
            curl_setopt($ch, CURLOPT_TIMEOUT_MS, 50000);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $xml_post_string);
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            set_time_limit(0);
            $soap = curl_exec($ch);
            $err = curl_error($ch);
        
            $err = curl_error($ch);
        curl_close($ch);
        if ($err) {
            throw new Exception("cURL Error #:" . $err);
        } else{
            return DownloadXmlRequest::response(DownloadXmlRequest::xml2array($soap));
        }
    }
    
    public static function getSoapBody($cert, $keyPEM, $rfc, $idPaquete){
      $dataToHash = '<des:PeticionDescargaMasivaTercerosEntrada xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx"><des:peticionDescarga IdPaquete="'.$idPaquete.'" RfcSolicitante="'.$rfc.'"></des:peticionDescarga></des:PeticionDescargaMasivaTercerosEntrada>';
      $digestValue = base64_encode(sha1($dataToHash, true));
      $dataToSign = '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod><DigestValue>'.$digestValue.'</DigestValue></Reference></SignedInfo>';
      openssl_sign($dataToSign, $digs, $keyPEM, OPENSSL_ALGO_SHA1);
      $datosCer = openssl_x509_parse(DownloadXmlRequest::der2pem($cert));
      $serialNumber = $datosCer["serialNumber"];
      $datos = '';
      foreach ($datosCer["issuer"] as $key => $value) {
        $datos .= $key.'='.$value.',';
      }
      $datos = substr($datos, 0, -1);
      $xml = '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx" xmlns:xd="http://www.w3.org/2000/09/xmldsig#"><s:Header/><s:Body><des:PeticionDescargaMasivaTercerosEntrada><des:peticionDescarga IdPaquete="'.$idPaquete.'" RfcSolicitante="'.$rfc.'"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod><DigestValue>'.$digestValue.'</DigestValue></Reference></SignedInfo><SignatureValue>'.base64_encode($digs).'</SignatureValue><KeyInfo><X509Data><X509IssuerSerial><X509IssuerName>'.$datos.'</X509IssuerName><X509SerialNumber>'.$serialNumber.'</X509SerialNumber></X509IssuerSerial><X509Certificate>'.base64_encode($cert).'</X509Certificate></X509Data></KeyInfo></Signature></des:peticionDescarga></des:PeticionDescargaMasivaTercerosEntrada></s:Body></s:Envelope>';
      return $xml;
    }

    public static function headers($xml_post_string, $token){
      return  array(
                   "Content-type: text/xml;charset=\"utf-8\"",
                   "Accept: text/xml",
                   "Authorization: WRAP access_token=\"".$token."\"",
                   "Cache-Control: no-cache",
                   "SOAPAction: http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar", 
                   "Content-length: ".strlen($xml_post_string),
               );
    }
    
    public static function xml2array($xml){
        return json_decode(json_encode(simplexml_load_string(str_replace("s:", "", str_replace("h:","", str_replace("u:","",'<?xml version="1.0" encoding="utf-8"?>'.$xml))))),TRUE);
    }
    
    public static function response($data){
        $obj = (object)[];
        if(isset($data["Body"]["Fault"])){
          $obj->faultcode = $data["Body"]["Fault"]["faultcode"];
          $obj->faultstring = $data["Body"]["Fault"]["faultstring"];
        }
        else{
          $obj->Paquete = $data["Body"]["RespuestaDescargaMasivaTercerosSalida"]["Paquete"];
        }
        return $obj;
    }

    public static function der2pem($der_data, $type='CERTIFICATE') {
        $pem = chunk_split(base64_encode($der_data), 64, "\n");
        $pem = "-----BEGIN ".$type."-----\n".$pem."-----END ".$type."-----\n";
        return $pem;
     }
}