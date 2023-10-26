<?php

# request
# sanitize
# keepValues
# hideValues
# csrf
# hashPass
# verifyPass
# add
# pattern
# run

session_id('SESSIONID');
session_start();

class CoreApp {

    protected $routes = [];
    
    public static $db;
    public static $auth = ['table' => 'users', 'logout' => '/', 'permission' => '/'];

    // Helper Functions

    public static function request(bool $server = false) {

        $object = [];
        $queries = [];

        parse_str($_SERVER['QUERY_STRING'], $queries);

        empty($server) ? false : $object['server'] = CoreApp::sanitize($_SERVER); 
        empty($queries) ? false : $object['queries'] = CoreApp::sanitize($queries);
        empty($_POST) ? false : $object['form'] = CoreApp::sanitize($_POST); 
        empty($_FILES) ? false : $object['files'] = CoreApp::sanitize($_FILES); 

        return $object;

    }

    public static function sanitize($data)
    {

        if (is_array($data)) {
            foreach ($data as $key => $value) {
                $data[is_string($key) ? CoreApp::sanitize($key) : $key] = CoreApp::sanitize($value);
            }
        }

        if (is_string($data)) {
            $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
        }

        return $data;

    }

    public static function keepValues(array $array, array $keys) {

        $parsed = [];

        foreach ($array as $key => $value) {
            if (in_array($key, $keys)) {
                $parsed[$key] = $value;
            } 
        }

        return $parsed;

    }

    public static function hideValues(array $array, array $keys) {

        $parsed = [];

        foreach ($array as $key => $value) {
            if (!in_array($key, $keys)) {
                $parsed[$key] = $value;
            } 
        }

        return $parsed;

    }

    public static function csrf (string $method) {

        if ($method == 'SET') {

            $token = bin2hex(sha1(rand().time()));

            $_SESSION['csrf_token'] = $token;

            return $token;

        } 

        if ($method == 'VERIFY') {

            if (isset($_POST['csrf_token']) || isset($_SESSION['csrf_token'])) {

                if (CoreApp::sanitize($_POST['csrf_token']) === CoreApp::sanitize($_SESSION['csrf_token'])) {

                    return true;

                }

            }

        }

        return false;

    }

    public static function hashPass($password) {

        return password_hash($password, PASSWORD_DEFAULT);

    }

    public static function verifyPass($password, $hash) {

        return password_verify($password, $hash);

    }

    // Adding routes

    public function add($method, $path, $function) {

        $this -> routes[$method][$path] = $function;

    }

    public function pattern($url, $method) {

        foreach ($this -> routes [$method] as $path => $function) {

            $pattern = preg_replace('/\/:([^\/]+)/', '/(?P<$1>[^/]+)', $path);

            if (preg_match('#^' . $pattern . '$#', $url, $matches)) {

                $parsing = array_filter($matches, 'is_string', ARRAY_FILTER_USE_KEY);

                call_user_func($function, ...$parsing);

                return false;

            }

        }

        return true;
    }

    public function run() {

        $method = htmlspecialchars($_SERVER['REQUEST_METHOD']);
        $url = explode('?', htmlspecialchars($_SERVER['REQUEST_URI']))[0];

        if (array_key_exists($method, $this -> routes)) {

            if ($this -> pattern($url, $method)) {

                require 'templates/404.php';

            }

            
        }

    }

    // Creating connection with database

    public function database (string $host, string $user, string $pass, string $name) {

        CoreApp::$db = new mysqli($host, $user, $pass, $name);

    }
    
    // Inserting in database

    public static function insert (string $table, array $fields) {

        $keys = array_keys($fields);
        $values = array_values($fields);

        $sql = '';

        $sql .= 'INSERT INTO ' . $table;
        $sql .= ' (' . implode(', ', $keys) . ')';
        $sql .= ' VALUES (' . substr(str_repeat('?,', count($values)), 0, -1) . ')';

        $statement = CoreApp::$db -> prepare($sql);

        return ($statement -> execute($values)) ? true : false;

    }

    // Unique Search

    public static function uniqueSearch(string $table, array $query) {

        $keys = array_keys($query);
        $values = array_values($query);

        $fields = implode(', ', $keys);

        $uniqueQuery = array_map(function($key) { return $key . ' = ? '; }, $keys);
        $uniqueQuery = implode(' AND ', $uniqueQuery);

        $sql = 'SELECT ' . $fields . ' FROM ' . $table;
        $sql .= ' WHERE ' . $uniqueQuery;

        $statement = CoreApp::$db -> prepare($sql);
        $statement -> execute($values);
        $statement = $statement -> get_result();

        return (!($statement -> num_rows)) ? true : false;

    }

    // Find

    public static function find(string $table, array $fields = [], array $query = []) {

        $keys = array_keys($query);
        $values = array_values($query);

        $fields =  empty($fields) ? '*' : implode(',', $fields);

        $uniqueQuery = array_map(function($key) { return $key . ' = ? '; }, $keys);
        $uniqueQuery = implode(' AND ', $uniqueQuery);

        $sql = 'SELECT ' . $fields . ' FROM ' . $table;
        $sql .= ' WHERE ' . $uniqueQuery . ' LIMIT 1 ';

        $statement = CoreApp::$db -> prepare($sql);
        $statement -> execute($values);
        $statement = $statement -> get_result();
        $result = $statement -> fetch_assoc();

        return $result;

    }

    // Selecting from database

    public static function select (
        string $table,
        array $fields = [],
        string $where = '', 
        array $values = [], 
        string $order = '',
        string $limit = ''
    ) {

        $fields =  empty($fields) ? '*' : implode(',', $fields);
        $sql = '';

        $sql .= 'SELECT ' . $fields . ' FROM ' . $table;
        $sql .= empty($where) ? '' : ' WHERE '. $where;
        $sql .= empty($order) ? '' : ' ORDER BY ' . $order;
        $sql .= empty($limit) ? '' : ' LIMIT ' . $limit;

        $statement = CoreApp::$db -> prepare($sql);

        if ($statement -> execute($values)) {

            $statement = $statement -> get_result();

            while ($row = $statement -> fetch_assoc()) {

                $result[] = $row;

            }

        } else {
            $result = false;
        }

        return $result;

    }

    // Updating database

    public static function update (string $table, string $set = '', string $where = '', array $values = []) {

        $sql = '';

        $sql .= 'UPDATE ' . $table;
        $sql .= ' SET ' . $set;
        $sql .= ' WHERE '. $where;

        $statement = CoreApp::$db -> prepare($sql);

        return ($statement -> execute($values)) ? true : false;

    }

    // Deleting from database

    public static function delete (string $table, string $where = '', array $values = []) {

        $sql = '';

        $sql .= 'DELETE FROM ' . $table;
        $sql .= empty($where) ? '' : ' WHERE '. $where;

        $statement = CoreApp::$db -> prepare($sql);

        return ($statement -> execute($values)) ? true : false;

    }

    // Session Flash

    public static function flash(string $method, string $key, string $value = '') {

        if ($method == 'SET') {

            $_SESSION[CoreApp::sanitize($key)] = CoreApp::sanitize($value ?? '');

        } else if ($method == 'DISPLAY') {

            $value = CoreApp::sanitize($_SESSION[$key] ?? false);
            unset($_SESSION[$key]);

            return $value;

        }

        return true;

    }

    // File Uploading

    public static function upload(array $file, string $filename, string $path, int $size = 1024, array $type = []) {

        $size *= 1000;

        if ($file) {

            $extension = pathinfo($file['name'])['extension'];

            if (!empty($type)) {

                if (!in_array($extension, $type)) {

                    return [false, 'extension'];

                }

            }

            if ($size < $file['size']) {

                return [false, 'size'];

            }

            if (move_uploaded_file($file['tmp_name'], $path.$filename)) {

                return [true, 'success'];

            }

            return [false, 'error'];

        } 

        return [false, 'file'];

    }

    // Authentication

    public static function register(array $user, array $unique) {

        $array = CoreApp::keepValues($user, $unique);

        if (CoreApp::uniqueSearch(CoreApp::$auth['table'], $array)) {

            $user['password'] = CoreApp::hashPass($user['password']);

            return CoreApp::insert(CoreApp::$auth['table'], $user);
     
        }

        return false;

    }

    public static function userVerify(string $token) {

        return CoreApp::update(CoreApp::$auth['table'], '_status = ?', '_verification = ?', ['active', $token]);

    }

    public static function login(array $credentials) {

        $array = CoreApp::hideValues($credentials, ['password']);

        $hash = CoreApp::find(CoreApp::$auth['table'], ['password'], $array);

        $session = md5(time().uniqid());
        $logout = time() + 3600;

        if (!empty($hash)) {

            if (CoreApp::verifyPass($credentials['password'], $hash['password'])) {

                CoreApp::update(
                    CoreApp::$auth['table'], 
                    '_session = ?, _logout = ?', 
                    'email = ?', 
                    [$session, $logout, $array['email']]
                );

                $_SESSION['user'] = $session;
                
                return 'true';

            }

        }

        return false;

    }

    public static function logout() {

        unset($_SESSION['user']);
        header('location: '. CoreApp::$auth['logout']);

        return true;

    }

    public static function permission() {

        header('location: '. CoreApp::$auth['permission']);
        return true;

    }

    public static function authenticate (array $roles = ['user']) {

        $user = CoreApp::find(CoreApp::$auth['table'], [], ['_session' => htmlspecialchars($_SESSION['user'])]);

        if ($user) {

            if ($user['_logout'] < time()) {

                return !CoreApp::logout();

            }

            if (!in_array($user['_roles'], $roles)) {

                return !CoreApp::permission();

            }

            return $user;

        }

        return false;

    }
    
    // API Calls

    public static function fetch(string $method, string $url, array $data = []) {

        $curl = curl_init();

        switch ($method)
        {
            case 'POST':

                curl_setopt($curl, CURLOPT_POST, 1);

                if ($data) {
                    curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
                }
                break;

            default:

                if ($data) {

                    $url = sprintf("%s?%s", $url, http_build_query($data));

                }
        }

        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);

        $result = curl_exec($curl);

        curl_close($curl);

        return empty($result) ? false : $result;

    }


    // Rendering PHP templates

    public static function render(string $file, array $data = []) {

        require 'templates/' . $file . '.php';

    }   

    public function __destruct() {

        (CoreApp::$db) ? CoreApp::$db -> close() : false;

    }

}