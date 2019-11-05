<?php
namespace think\sso;

use think\facade\Cache;
use think\facade\Session;
/**
 * Single sign-on server.
 *
 * The SSO server is responsible of managing users sessions which are available for clients.
 *
 * To use the SSO server, extend this class and implement the abstract methods.
 * This class may be used as controller in an MVC application.
 */
abstract class Server
{
    /**
     * @var array
     */
    protected $options = [];

    /**
     * @var string
     */
    protected $returnType;

    /**
     * @var mixed
     */
    protected $clientId;


    /**
     * Class constructor
     *
     * @param array $options
     */
    public function __construct(array $options = [])
    {
        $this->options = $options + $this->options;
    }


    /**
     * Start the session for client requests to the SSO server
     */
    public function startClientSession()
    {
        if (isset($this->clientId)) return;

        $sid = $this->getClientSessionID();

        if ($sid === false) {
            return $this->fail("Client didn't send a session key", 400);
        }

        $linkedId = Cache::get($sid);

        if (!$linkedId) {
            return $this->fail("The client session id isn't attached to a user session", 403);
        }

        if (session_status() === PHP_SESSION_ACTIVE) {
            if ($linkedId !== session_id()) throw new \Exception("Session has already started", 400);
            return;
        }

        session_id($linkedId);
        session_start();

        $this->clientId = $this->validateClientSessionId($sid);
    }

    /**
     * Get session ID from header Authorization or from $_GET/$_POST
     */
    protected function getClientSessionID()
    {
        if (!function_exists('getallheaders')) {
            $headers = array();
            foreach ($_SERVER as $name => $value) {
                if (substr($name, 0, 5) == 'HTTP_') {
                    $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
                }
            }
        } else {
            $headers = getallheaders();
        }

        if (isset($headers['Authorization']) &&  strpos($headers['Authorization'], 'Bearer') === 0) {
            $headers['Authorization'] = substr($headers['Authorization'], 7);
            return $headers['Authorization'];
        }
        if (isset($_GET['access_token'])) {
            return $_GET['access_token'];
        }
        if (isset($_POST['access_token'])) {
            return $_POST['access_token'];
        }
        if (isset($_GET['sso_session'])) {
            return $_GET['sso_session'];
        }

        return false;
    }

    /**
     * Validate the client session id
     *
     * @param string $sid session id
     * @return string  the client id
     */
    protected function validateClientSessionId($sid)
    {
        $matches = null;

        if (!preg_match('/^SSO-(\w*+)-(\w*+)-([a-z0-9]*+)$/', $this->getClientSessionID(), $matches)) {
            return $this->fail("Invalid session id");
        }

        $clientId = $matches[1];
        $token    = $matches[2];

        if ($this->generateSessionId($clientId, $token) != $sid) {
            return $this->fail("Checksum failed: Client IP address may have changed", 403);
        }

        return $clientId;
    }

    /**
     * Start the session when a user visits the SSO server
     */
    protected function startUserSession()
    {
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();
    }

    /**
     * Generate session id from session token
     *
     * @param string $clientId
     * @param string $token
     * @return string
     */
    protected function generateSessionId($clientId, $token)
    {
        $client = $this->getClientInfo($clientId);

        if (!isset($client)) return null;

        return "SSO-{$clientId}-{$token}-" . hash('sha256', 'session' . $token . $client['secret']);
    }

    /**
     * Generate session id from session token
     *
     * @param string $clientId
     * @param string $token
     * @return string
     */
    protected function generateAttachChecksum($clientId, $token)
    {
        $client = $this->getClientInfo($clientId);

        if (!isset($client)) return null;

        return hash('sha256', 'attach' . $token . $client['secret']);
    }


    /**
     * Detect the type for the HTTP response.
     * Should only be done for an `attach` request.
     */
    protected function detectReturnType()
    {
        if (!empty($_GET['return_url'])) {
            $this->returnType = 'redirect';
        } elseif (!empty($_GET['callback'])) {
            $this->returnType = 'jsonp';
        } elseif (strpos($_SERVER['HTTP_ACCEPT'], 'image/') !== false) {
            $this->returnType = 'image';
        } elseif (strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false) {
            $this->returnType = 'json';
        }
    }

    /**
     * Attach a user session to a client session
     */
    public function attach()
    {
        $this->detectReturnType();

        if (empty($_REQUEST['client'])) return $this->fail("No client specified", 400);
        if (empty($_REQUEST['token'])) return $this->fail("No token specified", 400);

        if (!$this->returnType) return $this->fail("No return url specified", 400);

        $checksum = $this->generateAttachChecksum($_REQUEST['client'], $_REQUEST['token']);

        if (empty($_REQUEST['checksum']) || $checksum != $_REQUEST['checksum']) {
            return $this->fail("Invalid checksum", 400);
        }

        $this->startUserSession();
        $sid = $this->generateSessionId($_REQUEST['client'], $_REQUEST['token']);

        Cache::set($sid, $this->getSessionData('id'));
        $this->outputAttachSuccess();
    }

    /**
     * Output on a successful attach
     */
    protected function outputAttachSuccess()
    {
        if ($this->returnType === 'image') {
            $this->outputImage();
        }

        if ($this->returnType === 'json') {
            header('Content-type: application/json; charset=UTF-8');
            echo json_encode(['success' => 'attached']);
        }

        if ($this->returnType === 'jsonp') {
            $data = json_encode(['success' => 'attached']);
            echo $_REQUEST['callback'] . "($data, 200);";
        }

        if ($this->returnType === 'redirect') {
            $url = $_REQUEST['return_url'];
            header("Location: $url", true, 307);
            echo "You're being redirected to <a href='{$url}'>$url</a>";
        }
    }

    /**
     * Output a 1x1px transparent image
     */
    protected function outputImage()
    {
        header('Content-Type: image/png');
        echo base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABAQ'
            . 'MAAAAl21bKAAAAA1BMVEUAAACnej3aAAAAAXRSTlMAQObYZg'
            . 'AAAApJREFUCNdjYAAAAAIAAeIhvDMAAAAASUVORK5CYII=');
    }


    /**
     * Authenticate
     */
    public function login()
    {
        $this->startClientSession();

        if (empty($_POST['username'])) $this->fail("No username specified", 400);
        if (empty($_POST['password'])) $this->fail("No password specified", 400);

        $validation = $this->authenticate($_POST['username'], $_POST['password']);

        if ($validation->failed()) {
            return $this->fail($validation->getError(), 400);
        }

        $this->setSessionData('sso_user', $_POST['username']);
        $this->userInfo();
    }

    /**
     * Log out
     */
    public function logout()
    {
        $this->startClientSession();
        $this->setSessionData('sso_user', null);

        header('Content-type: application/json; charset=UTF-8');
        http_response_code(204);
    }

    /**
     * Ouput user information as json.
     */
    public function userInfo()
    {
        $this->startClientSession();
        $user = null;

        $username = $this->getSessionData('sso_user');

        if ($username) {
            $user = $this->getUserInfo($username);
            if (!$user) return $this->fail("User not found", 500); // Shouldn't happen
        }

        header('Content-type: application/json; charset=UTF-8');
        echo json_encode($user);
    }


    /**
     * Set session data
     *
     * @param string $key
     * @param string $value
     */
    protected function setSessionData($key, $value)
    {
        if (!isset($value)) {
            Session::delete($key);
            return;
        }

        Session::set($key, $vlaue);
    }

    /**
     * Get session data
     *
     * @param type $key
     */
    protected function getSessionData($key)
    {
        if ($key === 'id') return session_id();

        return Session::has($key) ? Session::get($key): null;
    }


    /**
     * An error occured.
     *
     * @param string $message
     * @param int    $http_status
     */
    protected function fail($message, $http_status = 500)
    {
        if (!empty($this->options['fail_exception'])) {
            throw new Exception($message, $http_status);
        }

        if ($http_status === 500) trigger_error($message, E_USER_WARNING);

        if ($this->returnType === 'jsonp') {
            echo $_REQUEST['callback'] . "(" . json_encode(['error' => $message]) . ", $http_status);";
            exit();
        }

        if ($this->returnType === 'redirect') {
            $url = $_REQUEST['return_url'] . '?sso_error=' . $message;
            header("Location: $url", true, 307);
            echo "You're being redirected to <a href='{$url}'>$url</a>";
            exit();
        }

        http_response_code($http_status);
        header('Content-type: application/json; charset=UTF-8');

        echo json_encode(['error' => $message]);
        exit();
    }


    /**
     * Authenticate using user credentials
     *
     * @param string $username
     * @param string $password
     * @return \Jasny\ValidationResult
     */
    abstract protected function authenticate($username, $password);

    /**
     * Get the secret key and other info of a client
     *
     * @param string $clientId
     * @return array
     */
    abstract protected function getClientInfo($clientId);

    /**
     * Get the information about a user
     *
     * @param string $username
     * @return array|object
     */
    abstract protected function getUserInfo($username);
}

