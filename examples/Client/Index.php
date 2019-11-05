<?php
require_once '../common.php';

use think\sso\Client;

if (isset($_GET['sso_error'])) {
    header("Location: error.php?sso_error=" . $_GET['sso_error'], true, 307);
    exit;
}

$client = new Client($config['sso_url'], $config['client_id'], $config['client_secret']);
$client->attach(true);

try {
    $user = $client->getUserInfo();
} catch (\Exception $e) {
    header('Location: ' . $_SERVER['REQUEST_URI']);
    exit;
} catch (\Exception $e) {
    header("Location: error.php?sso_error=" . $e->getMessage(), true, 307);
}

if (!$user) {
    header("Location: login.php", true, 307);
    exit;
}
?>
<!doctype html>
<html>
    <head>
        <title><?= $client->broker ?> (Single Sign-On demo)</title>
        <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container">
            <h1><?= $client->broker ?> <small>(Single Sign-On demo)</small></h1>
            <h3>Logged in</h3>

            <pre><?= json_encode($user, JSON_PRETTY_PRINT); ?></pre>

            <a id="logout" class="btn btn-default" href="login.php?logout=1">Logout</a>
        </div>
    </body>
</html>

