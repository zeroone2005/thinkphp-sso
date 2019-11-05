<?php
require_once '../common.php';
require_once 'SSOServer.php';

$ssoServer = new SSOServer();

$command = isset($_REQUEST['command']) ? $_REQUEST['command'] : null;
if (!$command || !method_exists($ssoServer, $command)) {
    header("HTTP/1.1 404 Not Found");
    header('Content-type: application/json; charset=UTF-8');
    
    echo json_encode(['error' => 'Unknown command']);
    exit();
}
$result = $ssoServer->$command();