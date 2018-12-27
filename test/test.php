<?php
require_once '../SWInclude.php';
use src\LoginXmlRequest as loginSAT;
use src\RequestXmlRequest as solicita;
use src\VerifyXmlRequest as verifica;
use src\Utils as util;


$cert = file_get_contents('resources/cer.cer');
$key = file_get_contents('resources/key.pem');
$rfc = 'LAN7008173R5';
$fechaInicial = '2018-06-02T00:00:00';
$fechaFinal = '2018-06-02T12:59:59';
$TipoSolicitud = 'CFDI';
$idSolicitud = '1fb832ff-6a25-4616-8ca8-04478690cc29';
$idPaquete = '1fb832ff-6a25-4616-8ca8-04478690cc29_01';
$ResponseAuth = loginSAT::soapRequest($cert,$key);
var_dump($ResponseAuth);

$ResponseRequest = solicita::soapRequest($cert, $key, $ResponseAuth->token, $rfc, $fechaInicial, $fechaFinal, $TipoSolicitud);
var_dump($ResponseRequest);

$ResponseVerify = verifica::soapRequest($cert, $key, $ResponseAuth->token, $rfc, $idSolicitud);
var_dump($ResponseVerify);

$ResponseDownload = descarga::soapRequest($cert, $key, $ResponseAuth->token, $rfc, $idPaquete);
util::saveBase64File($ResponseDownload->Paquete, $idPaquete.".zip");
var_dump($ResponseDownload);

?>