<?php
require_once '../SWInclude.php';
use src\LoginXmlRequest as loginSAT;
use src\RequestXmlRequest as solicita;
use src\VerifyXmlRequest as verifica;


$cert = file_get_contents('resources/cer.cer');
$key = file_get_contents('resources/key.pem');
$rfc = 'LAN7008173R5';
$fechaInicial = '2018-06-02T00:00:00';
$fechaFinal = '2018-06-02T12:59:59';
$TipoSolicitud = 'CFDI';
$idSolicitud = '1fb832ff-6a25-4616-8ca8-04478690cc29';
$resultado = loginSAT::soapRequest($cert,$key);
var_dump($resultado);

$resultado2 = solicita::soapRequest($cert, $key, $resultado->token, $rfc, $fechaInicial, $fechaFinal, $TipoSolicitud);
var_dump($resultado2);

$resultado3 = verifica::soapRequest($cert, $key, $resultado->token, $rfc, $idSolicitud);
var_dump($resultado3);

?>