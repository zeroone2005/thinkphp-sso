<?php

use Jasny\ValidationResult;
use think\sso\Server;

/**
 * Example SSO server.
 * 
 * Normally you'd fetch the broker info and user info from a database, rather then declaring them in the code.
 */
class SSOServer extends Server
{
    /**
     * Registered brokers
     * @var array
     */
    private static $brokers = [
        'Alice' => ['secret'=>'8iwzik1bwd'],
        'Greg' => ['secret'=>'7pypoox2pc'],
        'Julias' => ['secret'=>'ceda63kmhp']
    ];

    /**
     * System users
     * @var array
     */
    private static $users = array (
        'jackie' => [
            'fullname' => 'Jackie Black',
            'email' => 'jackie.black@example.com',
            'password' => '$2y$10$lVUeiphXLAm4pz6l7lF9i.6IelAqRxV4gCBu8GBGhCpaRb6o0qzUO' // jackie123
        ],
        'john' => [
            'fullname' => 'John Doe',
            'email' => 'john.doe@example.com',
            'password' => '$2y$10$RU85KDMhbh8pDhpvzL6C5.kD3qWpzXARZBzJ5oJ2mFoW7Ren.apC2' // john123
        ],
    );

    /**
     * Get the API secret of a broker and other info
     *
     * @param string $brokerId
     * @return array
     */
    protected function getBrokerInfo($brokerId)
    {
        return isset(self::$brokers[$brokerId]) ? self::$brokers[$brokerId] : null;
    }

    /**
     * Authenticate using user credentials
     *
     * @param string $username
     * @param string $password
     * @return boolean
     */
    protected function authenticate($username, $password)
    {
        if (!isset($username)) {
            return ['status' => false, 'msg' => 'username isn\'t set'];
        }
        
        if (!isset($password)) {
            return ['status' => false, 'msg' => 'password isn\'t set'];
        } 
        
        if (!isset(self::$users[$username]) || !password_verify($password, self::$users[$username]['password'])) {
            return ['status' => false, 'msg' => 'Invalid credentials'];
        }

        return true;
    }


    /**
     * Get the user information
     *
     * @return array
     */
    protected function getUserInfo($username)
    {
        if (!isset(self::$users[$username])) return null;
    
        $user = compact('username') + self::$users[$username];
        unset($user['password']);
        
        return $user;
    }
}
