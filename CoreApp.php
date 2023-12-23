<?php

/**
 * CoreApp Framework
 *
 * @author Anirudh Singh
 * @link https://github.com/violentanirudh/coreapp
 *
 * @description
 * CoreApp is a PHP framework designed for rapid development of CRUD applications. It provides essential features
 * for routing, request and response handling, rendering, security, database operations, API calls, utilities,
 * authentication, and more. The framework aims to streamline the development process and offers flexibility for
 * medium-level websites.
 *
 * @license MIT License
 * @version 1.0.0
 *
 * @usage
 * 1. Ensure proper configuration in CoreApp::database() for database connection and other settings.
 * 2. Create routes using CoreApp::add() to define the URL patterns and associated functions.
 * 3. Utilize CoreApp::run() to start the framework and handle incoming requests.
 *
 * @notes
 * - This framework follows the MIT License. Refer to the LICENSE file for details.
 * - For the latest updates and contributions, visit the GitHub repository.
 */

class CoreApp {

    // Associative array to store routing configurations
    protected $routes = [];

    // Flag indicating the operational mode (development/production)
    public static $mode = false;

    // Database connection object
    public static $db;

    // Application configuration settings
    public static $config;

    // User authentication configuration
    public static $auth = [
        'table' => 'users',    // Database table for user authentication
        'logout' => '/',        // URL to redirect users after logout
        'permission' => '/',    // URL to redirect unauthorized users
    ];

    // Routing

    /**
     * Add a route to the routing table.
     * @param string $method   The HTTP method (GET, POST, etc.).
     * @param string $path     The URL path pattern.
     * @param callable $function The callback function to execute for the route.
    */
    public function add(string $method, string $path, callable $function) {
        $this->routes[$method][$path] = $function;
    }

    /**
     * Match the given URL path against the registered routes and execute the corresponding callback.
     * @param string $url     The requested URL path.
     * @param string $method  The HTTP method of the request.
    */
    public function match(string $url, string $method) {
        foreach ($this->routes[$method] as $path => $function) {
            // Convert route path to a regex pattern
            $pattern = $this->pathConverter($path);

            // Check if the URL matches the route pattern
            if (preg_match('#^' . $pattern . '$#', $url, $matches)) {
                // Extract named parameters from the URL
                $params = array_filter($matches, 'is_string', ARRAY_FILTER_USE_KEY);

                // Execute the callback function with the extracted parameters
                call_user_func($function, ...$params);
                return;
            }
        }

        // If no matching route is found, handle as a 404 Not Found
        $this->handleNotFound();
    }

    /**
     * Convert a route path to a regex pattern for matching.
     * @param string $path The route path.
     * @return string The converted regex pattern.
    */
    private function pathConverter(string $path): string {
        return preg_replace('/\/:([^\/]+)/', '/(?P<$1>[^/]+)', $path);
    }

    // Handle the case where no matching route is found (404 Not Found).
    private function handleNotFound() {
        require 'templates/notfound.php';
    }

    // Run the application by processing the current request.
    public function run() {
        $method = htmlspecialchars($_SERVER['REQUEST_METHOD']);
        $url = explode('?', htmlspecialchars($_SERVER['REQUEST_URI']))[0];

        // Check if the requested method is registered in the routing table
        if (array_key_exists($method, $this->routes)) {
            // Match the requested URL against the registered routes
            $this->match($url, $method);
        }
    }

    // Request and Response

    /**
     * Process the current request and return an array with sanitized input data.
     * @param bool $server Whether to include server data in the result.
     * @return array The processed request data.
    */
    public static function request(bool $server = false): array {
        $requestData = [];

        // Parse query string into an array
        parse_str($_SERVER['QUERY_STRING'], $queries);

        // Include server data in the result if requested
        empty($server) ?: $requestData['server'] = CoreApp::sanitize($_SERVER);

        // Include query data in the result if present
        empty($queries) ?: $requestData['queries'] = CoreApp::sanitize($queries);

        // Include file data in the result if present
        empty($_FILES) ?: $requestData['files'] = CoreApp::sanitize($_FILES);

        // Include form data in the result if present
        empty($_POST) ?: $requestData['form'] = CoreApp::sanitize($_POST);

        return $requestData;
    }

    /**
     * Get the value of a specific input from the request.
     * @param string $name The name of the input field.
     * @return mixed|null The value of the input field or null if not found.
    */
    public static function input(string $name) {
        return $_POST[$name] ?? null;
    }

    /**
     * Validate a value against a specified validation type.
     * @param string $type The type of validation to perform.
     * @param string $value The value to validate.
     * @return bool Whether the validation is successful.
    */
    public static function validate(string $type, string $value): bool {
        $type = strtolower($type);

        switch ($type) {
            case 'text':
                return preg_match("/^[a-zA-Z0-9-' ]*$/", $value);
            case 'email':
                return filter_var($value, FILTER_VALIDATE_EMAIL);
            case 'password':
                return preg_match('#.*^(?=.{8,20})(?=.*[a-zA-Z])(?=.*[0-9])(?=.*\W).*$#', $value);
            case 'url':
                return preg_match('/\b(?:(?:https?|ftp):\/\/|www\.)[-a-z0-9+&@#\/%?=~_|!:,.;]*[-a-z0-9+&@#\/%=~_|]/i', $value);
            default:
                return false;
        }
    }

    /**
     * Sanitize input data to prevent security vulnerabilities.
     * @param mixed $data The data to sanitize (can be an array or string).
     * @return mixed The sanitized data.
    */
    public static function sanitize($data) {
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

    // Rendering

    public static function render(string $file, array $data = []) {
        // Include the template file
        $templatePath = 'templates/' . $file . '.php';

        // Check if the template file exists
        if (file_exists($templatePath)) {
            // Extract the data for easy access in the template
            extract($data);

            // Include the template
            include $templatePath;
        } else {
            // Handle error if the template file doesn't exist
            $this->handleNotFound();
        }
    }

    // Security

    /**
     * Set security headers for the response.
     * @param bool $csp Whether to include Content Security Policy header.
     * @param bool $frame Whether to include X-Frame-Options header.
     * @param bool $enableCors Whether to enable CORS headers.
     * @return void
    */
    public static function helmet(bool $csp = true, bool $frame = true, bool $cors = false) {
        // Content Security Policy
        if ($csp) {
            $cspDirective = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'";
            header("Content-Security-Policy: $cspDirective");
        }

        // X-Frame-Options
        if ($frame) {
            header("X-Frame-Options: DENY");
        }

        // Common security headers
        header("X-Content-Type-Options: nosniff");
        header('X-XSS-Protection: 1; mode=block');
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');

        // CORS headers
        if ($cors) {
            header('Access-Control-Allow-Origin: *');
            header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
            header('Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept');
        }

        // X-Powered-By header with site name
        $poweredByHeader = 'X-Powered-By: ' . CoreApp::$config['sitename'];
        header($poweredByHeader);
    }

    // Database

    /**
     * Create a database connection.
     * @param string $host Database host.
     * @param string $user Database username.
     * @param string $pass Database password.
     * @param string $name Database name.
     * @return void
     */
    public function database(string $host, string $user, string $pass, string $name) {
        CoreApp::$db = new mysqli($host, $user, $pass, $name);
    }

    /**
     * Insert data into a table.
     * @param string $table Name of the table.
     * @param array $fields Associative array of column names and values.
     * @return bool True on success, false on failure.
     */
    public static function insert(string $table, array $fields) {
        // Separate keys and values from the fields array.
        $keys = implode(', ', array_keys($fields));
        $values = array_values($fields);

        // Build the SQL query.
        $sql = "INSERT INTO $table ($keys) VALUES (" . rtrim(str_repeat('?,', count($values)), ',') . ")";

        // Prepare and execute the SQL statement.
        $statement = CoreApp::$db->prepare($sql);

        return $statement->execute($values);
    }

    /**
     * Check if a record with specified conditions exists in a table.
     * @param string $table Name of the table.
     * @param array $query Associative array of column names and values to search.
     * @return bool True if record exists, false otherwise.
     */
    public static function uniqueSearch(string $table, array $query) {
        $keys = array_keys($query);
        $values = array_values($query);

        $fields = implode(', ', $keys);

        $uniqueQuery = array_map(function ($key) {
            return $key . ' = ? ';
        }, $keys);
        $uniqueQuery = implode(' AND ', $uniqueQuery);

        $sql = 'SELECT ' . $fields . ' FROM ' . $table;
        $sql .= ' WHERE ' . $uniqueQuery;

        $statement = CoreApp::$db->prepare($sql);
        $statement->execute($values);
        $statement = $statement->get_result();

        return ($statement->num_rows) > 0;
    }

    /**
     * Find and retrieve a single record from a table based on conditions.
     * @param string $table Name of the table.
     * @param array $fields Columns to retrieve (empty array for all columns).
     * @param array $query Associative array of column names and values to search.
     * @return array|null Associative array representing the record, or null if not found.
     */
    public static function find(string $table, array $fields = [], array $query = []) {
        $keys = array_keys($query);
        $values = array_values($query);

        $fields = empty($fields) ? '*' : implode(',', $fields);

        $uniqueQuery = array_map(function ($key) {
            return $key . ' = ? ';
        }, $keys);
        $uniqueQuery = implode(' AND ', $uniqueQuery);

        $sql = 'SELECT ' . $fields . ' FROM ' . $table;
        $sql .= ' WHERE ' . $uniqueQuery . ' LIMIT 1 ';

        $statement = CoreApp::$db->prepare($sql);
        $statement->execute($values);
        $statement = $statement->get_result();
        $result = $statement->fetch_assoc();

        return $result;
    }

    /**
     * Retrieve records from a table based on conditions.
     * @param string $table Name of the table.
     * @param array $fields Columns to retrieve (empty array for all columns).
     * @param string $where WHERE clause conditions.
     * @param array $values Values to bind to the WHERE clause.
     * @param string $order ORDER BY clause.
     * @param string $limit LIMIT clause.
     * @return array|bool Array of records or false on failure.
     */
    public static function select(
        string $table,
        array $fields = [],
        string $where = '',
        array $values = [],
        string $order = '',
        string $limit = ''
    ) {
        $fields = empty($fields) ? '*' : implode(',', $fields);
        $sql = '';

        $sql .= 'SELECT ' . $fields . ' FROM ' . $table;
        $sql .= empty($where) ? '' : ' WHERE ' . $where;
        $sql .= empty($order) ? '' : ' ORDER BY ' . $order;
        $sql .= empty($limit) ? '' : ' LIMIT ' . $limit;

        $statement = CoreApp::$db->prepare($sql);

        if ($statement->execute($values)) {
            $result = [];

            $statement = $statement->get_result();

            while ($row = $statement->fetch_assoc()) {
                $result[] = $row;
            }
        } else {
            $result = false;
        }

        return $result;
    }

     /**
     * Update records in a table based on conditions.
     * @param string $table Name of the table.
     * @param string $set SET clause.
     * @param string $where WHERE clause conditions.
     * @param array $values Values to bind to the WHERE clause.
     * @return bool True on success, false on failure.
     */
    public static function update(string $table, string $set = '', string $where = '', array $values = []) {
        $sql = '';

        $sql .= 'UPDATE ' . $table;
        $sql .= ' SET ' . $set;
        $sql .= ' WHERE ' . $where;

        $statement = CoreApp::$db->prepare($sql);

        return ($statement->execute($values)) ? true : false;
    }

    /**
     * Delete records from a table based on conditions.
     * @param string $table Name of the table.
     * @param string $where WHERE clause conditions.
     * @param array $values Values to bind to the WHERE clause.
     * @return bool True on success, false on failure.
     */
    public static function delete(string $table, string $where = '', array $values = []) {
        $sql = '';

        $sql .= 'DELETE FROM ' . $table;
        $sql .= empty($where) ? '' : ' WHERE ' . $where;

        $statement = CoreApp::$db->prepare($sql);

        return ($statement->execute($values)) ? true : false;
    }

    /**
     * Execute a SQL query and return the result.
     * Currently supports 'count' method to count records in a table.
     * @param string $table Name of the table.
     * @param string $method SQL query method.
     * @return mixed Result of the query.
     */
    public static function sqlQuery(string $table, string $method) {
        if (strtolower($method) == 'count') {
            $sql = 'SELECT COUNT(id) FROM ' . $table;

            $statement = CoreApp::$db->prepare($sql);
            $statement->execute();
            $statement->bind_result($rows);
            $statement->fetch();

            return $rows;
        }
    }

    // API

    /**
     * Make an HTTP request to an external API.
     * @param string $method HTTP method (GET, POST, OPTIONS, etc.).
     * @param string $url URL of the API endpoint.
     * @param array $data Data to send in the request (for POST requests).
     * @return mixed Result of the API request.
     */
    public static function fetch(string $method, string $url, array $data = []) {
        $curl = curl_init();

        switch ($method) {
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

    // Utilities

    /**
     * Get the base URL of the application.
     *
     * @return string The base URL with the appropriate protocol.
     */
    public static function host() {
        // Check if the request is using HTTPS and set the protocol accordingly.
        $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https://' : 'http://';

        // Get the host from the server and return the formatted URL.
        $host = $_SERVER['HTTP_HOST'];
        return htmlspecialchars($protocol) . htmlspecialchars($host);
    }

    /**
     * Generate a slug from the given text.
     *
     * @param string $text The text to convert into a slug.
     * @return string The generated slug.
     */
    public static function slug($text) {
        // Replace non-alphanumeric characters with dashes and convert to lowercase.
        $text = preg_replace('/[^A-Za-z0-9-]+/', '-', $text);
        return strtolower($text);
    }


    /**
     * Manage session flash data.
     *
     * @param string $method The flash operation ('SET' or 'DISPLAY').
     * @param string $key The key to identify the flash data.
     * @param array $value The value to store in the flash data (used with 'SET' method).
     * @return mixed Returns the flash value when using 'DISPLAY' method, true for 'SET' method, or false on failure.
     */
    public static function flash(string $method, string $key, array $value = []) {
        if ($method == 'SET') {
            // Set flash data in the session.
            $_SESSION[CoreApp::sanitize($key)] = CoreApp::sanitize($value ?? '');
        } elseif ($method == 'DISPLAY') {
            // Display and unset flash data from the session.
            $value = CoreApp::sanitize($_SESSION[$key] ?? false);
            unset($_SESSION[$key]);
            return $value;
        }

        return true;
    }


    /**
     * Encrypt a text using AES-256-CBC encryption.
     *
     * @param string $text The plain text to encrypt.
     * @param string $key The encryption key.
     * @return string The encrypted and base64-encoded text.
     */
    public static function encrypt(string $text, string $key) {
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $encrypted = openssl_encrypt($text, 'aes-256-cbc', $key, 0, $iv);
        $encoded = bin2hex($iv) . bin2hex($encrypted);
        return base64_encode($encoded);
    }

    /**
     * Decrypt an AES-256-CBC encrypted text.
     *
     * @param string $text The base64-encoded text to decrypt.
     * @param string $key The decryption key.
     * @return string|false The decrypted plain text, or false on failure.
     */
    public static function decrypt(string $text, string $key) {
        $decoded = base64_decode($text);
        $iv = hex2bin(substr($decoded, 0, openssl_cipher_iv_length('aes-256-cbc') * 2));
        $encrypted = hex2bin(substr($decoded, openssl_cipher_iv_length('aes-256-cbc') * 2));
        $decrypted = openssl_decrypt($encrypted, 'aes-256-cbc', $key, 0, $iv);
        return $decrypted !== false ? $decrypted : false;
    }


    /**
     * Hash a password using the default PHP password hashing algorithm.
     *
     * @param string $password The plain text password to hash.
     * @return string The hashed password.
     */
    public static function hashPass(string $password) {
        return password_hash($password, PASSWORD_DEFAULT);
    }

    /**
     * Verify a password against its hashed counterpart.
     *
     * @param string $password The plain text password to verify.
     * @param string $hash The hashed password to compare against.
     * @return bool Returns true if the password matches the hash, false otherwise.
     */
    public static function verifyPass(string $password, string $hash) {
        return password_verify($password, $hash);
    }


    /**
     * Sends an HTTP response based on the specified format.
     *
     * @param mixed  $data       The data to be included in the response.
     * @param string $format     The desired response format ('json', 'plain', 'redirect').
     *
     * @return void              The function echoes the response and does not return a value.
     */
    public static function response($data, $format = 'json') {

        // Set the appropriate Content-Type header based on the response format
        switch ($format) {
            case 'json':
                header('Content-Type: application/json');
                echo json_encode($data);
                break;
            case 'plain':
                header('Content-Type: text/plain');
                echo $data;
                break;
            case 'redirect':
                // Redirect to the specified URL
                header('Location: ' . $data);
                break;
            default:
                // If an invalid response format is provided, return an error in JSON format
                header('Content-Type: application/json');
                echo json_encode(['error' => 'Invalid response format']);
        }
    }


    /**
     * Filters an array to keep only specified keys.
     * @param array $array The input array.
     * @param array $keys The keys to keep.
     * @return array The filtered array.
     */
    public static function keepValues(array $array, array $keys) {
        $parsed = [];

        foreach ($array as $key => $value) {
            if (in_array($key, $keys)) {
                $parsed[$key] = $value;
            }
        }

        return $parsed;
    }

    /**
     * Filters an array to hide specified keys.
     * @param array $array The input array.
     * @param array $keys The keys to hide.
     * @return array The filtered array.
     */
    public static function hideValues(array $array, array $keys) {
        $parsed = [];

        foreach ($array as $key => $value) {
            if (!in_array($key, $keys)) {
                $parsed[$key] = $value;
            }
        }

        return $parsed;
    }


    /**
     * Convert Markdown text to HTML using a simple parsing logic.
     * @param string $markdown Markdown text to be converted.
     * @return string Converted HTML.
     */
    public static function parsedown(string $markdown) {
        // Convert Markdown headings to HTML h2 tags
        $markdown = preg_replace('/^## (.+)$/m', '<h2>$1</h2>', $markdown);

        // Convert {{ and -- to unordered list tags
        $markdown = preg_replace('/\{\{/i', '<ul>', $markdown);
        $markdown = preg_replace('/\-\- (.+)$/m', '<li>$1</li>', $markdown);
        $markdown = preg_replace('/\}\}/i', '</ul>', $markdown);

        // Convert inline code to HTML code tags
        $markdown = preg_replace('/`([^`]+)`/', '<code>$1</code>', $markdown);

        // Convert markdown links to HTML anchor tags
        $markdown = preg_replace('/\[([^\]]+)\]\(([^)]+)\)/', '<a href="$2">$1</a>', $markdown);

        // Convert bold text to HTML strong tags
        $markdown = preg_replace('/\*\*(.*?)\*\*/', '<strong>$1</strong>', $markdown);

        // Convert newline characters to HTML line breaks
        $markdown = preg_replace('/(?<!\S)\n(?!\S)/', '<br>', $markdown);

        return $markdown;
    }

    // File System

    /**
     * Uploads a file to the specified path with optional size and type restrictions.
     *
     * @param array  $file       The $_FILES array representing the uploaded file.
     * @param string $filename   The desired filename for the uploaded file.
     * @param string $path       The destination path where the file will be stored.
     * @param int    $size       The maximum allowed size for the file in kilobytes.
     * @param array  $type       An array of allowed file extensions.
     *
     * @return array             An array indicating the result of the upload operation.
     *                           - If successful, [true, 'success'] is returned.
     *                           - If the file is not provided, [false, 'file'] is returned.
     *                           - If the file extension is not allowed, [false, 'extension'] is returned.
     *                           - If the file size exceeds the limit, [false, 'size'] is returned.
     *                           - If an error occurs during the upload, [false, 'error'] is returned.
     */
    public static function upload(array $file, string $filename, string $path, int $size = 1024, array $type = []) {

        // Convert size to bytes
        $size *= 1000;

        // Check if the file array is empty or required fields are not present
        if (empty($file) || !isset($file['name']) || !isset($file['size']) || !isset($file['tmp_name'])) {
            return [false, 'file'];
        }

        // Extract the file extension
        $extension = pathinfo($file['name'])['extension'];

        // Check if file extension is allowed
        if (!empty($type) && !in_array($extension, $type)) {
            return [false, 'extension'];
        }

        // Check if file size exceeds the limit
        if ($size < $file['size']) {
            return [false, 'size'];
        }

        // Attempt to move the uploaded file to the specified path
        if (move_uploaded_file($file['tmp_name'], $path . $filename)) {
            return [true, 'success'];
        }

        // If an error occurs during the upload process
        return [false, 'error'];
    }


    /**
     * Read the content of a file.
     * @param string $filename Name of the file to read.
     * @return string|false Content of the file or false if the file doesn't exist.
     */
    public static function fileRead($filename) {
        return file_exists($filename) ? file_get_contents($filename) : false;
    }

    /**
     * Write content to a file.
     * @param string $filename Name of the file to write to.
     * @param string $content Content to write to the file.
     * @return bool True on success, false on failure.
     */
    public static function fileWrite(string $filename, string $content) {
        $file = fopen($filename, 'w');

        fwrite($file, $content);
        fclose($file);

        return true;
    }

    // Authentication

    /**
     * Register a new user in the system.
     * @param array $user An array containing user information.
     * @param array $unique An array specifying unique fields for user registration.
     * @return bool True if registration is successful, false otherwise.
     */
    public static function register(array $user, array $unique) {
        $array = CoreApp::keepValues($user, $unique);

        if (CoreApp::uniqueSearch(CoreApp::$auth['table'], $array)) {
            $user['password'] = CoreApp::hashPass($user['password']);
            return CoreApp::insert(CoreApp::$auth['table'], $user);
        }

        return false;
    }

    /**
     * Verify a user using a token (e.g., during account activation).
     * @param string $token The verification token associated with the user.
     * @return bool True if verification is successful, false otherwise.
     */
    public static function userVerify(string $token) {
        return CoreApp::update(CoreApp::$auth['table'], '_status = ?', '_verification = ?', ['active', $token]);
    }

    /**
     * Log in a user with provided credentials.
     * @param array $credentials An array containing user login credentials.
     * @return bool True if login is successful, false otherwise.
     */
    public static function login(array $credentials) {
        $array = CoreApp::hideValues($credentials, ['password']);
        $hash = CoreApp::find(CoreApp::$auth['table'], ['password'], $array);
        $session = md5(time() . uniqid());
        $logout = time() + 3600;

        if (!empty($hash) && CoreApp::verifyPass($credentials['password'], $hash['password'])) {
            CoreApp::update(CoreApp::$auth['table'], '_session = ?, _logout = ?', 'email = ?', [$session, $logout, $array['email']]);
            $_SESSION['authUser'] = $session;
            return true;
        }

        return false;
    }

    /**
     * Log out the current user.
     * @return bool True if logout is successful, false otherwise.
     */
    public static function logout() {
        unset($_SESSION['authUser']);
        header('location: ' . CoreApp::$auth['logout']);
        return true;
    }

    /**
     * Redirect unauthorized users to a permission page.
     * @return bool Always returns true to indicate permission redirection.
     */
    public static function permission() {
        header('location: ' . CoreApp::$auth['permission']);
        return true;
    }

    /**
     * Check if a user is currently authenticated.
     * @return bool True if the user is authenticated, false otherwise.
     */
    public static function authSession() {
        return isset($_SESSION['authUser']);
    }

    /**
     * Get user information and check roles for authorization.
     * @param array $roles An array of roles to check against the user's roles.
     * @return array|bool An array containing user information if authorized, false otherwise.
     */
    public static function authUser(array $roles = []) {
        // Check if roles are provided
        if (empty($roles)) {
            return false; // No roles provided, unauthorized
        }

        // Check if user is authenticated
        if (isset($_SESSION['authUser'])) {
            // Get user information based on session
            $user = CoreApp::find(CoreApp::$auth['table'], [], ['_session' => htmlspecialchars($_SESSION['authUser'])]);

            if ($user) {
                // Check if user logout time has not expired
                if ($user['_logout'] >= time()) {
                    // Check if user has the required role
                    if (in_array($user['_roles'], $roles)) {
                        return $user; // User is authorized
                    } else {
                        return !CoreApp::permission(); // Redirect to permission page
                    }
                } else {
                    return !CoreApp::logout(); // User session has expired, perform logout
                }
            }
        }

        return false; // User is not authenticated
    }

    // Operational Mode

    /**
     * Load configuration settings from the database and store them in the configuration array.
     *
     * @param string $table The table name in the database containing configuration settings.
     * @return void
     */
    public static function loadConfig(string $table) {
        try {
            // Select configuration settings from the specified table.
            $config = CoreApp::select($table, ['setting', 'value']);

            // Iterate through configuration settings and store them in the configuration array.
            foreach ($config as $configuration) {
                CoreApp::$config[$configuration['setting']] = $configuration['value'];
            }
        } catch (Exception $e) {
            // Handle exceptions, redirect to error page, or log the error as needed.
            CoreApp::customException($e);
        }
    }

    public static function production(bool $value = false) {
        // Check if a value is provided
        if ($value) {
            CoreApp::$mode = true; // Set operational mode
        }

        return CoreApp::$mode; // Return current operational mode
    }

    // Error and Exception Handling

    /**
     * Custom error handler for handling PHP errors.
     * @param int $status The error level.
     * @param string $error The error message.
     * @param string $file The file in which the error occurred.
     * @param int $line The line number where the error occurred.
     */
    public static function customError($status, $error, $file, $line) {
        // Check if in production mode
        if (CoreApp::$mode) {
            header('location: /error'); // Redirect to the error page
            return false;
        }

        // Display error details in development mode
        echo "<b>Error:</b> [$status] $error in $file on line $line<br>";
        die();
    }

    /**
     * Custom exception handler for handling uncaught exceptions.
     * @param Exception $exception The uncaught exception.
     */
    public static function customException($exception) {
        // Check if in production mode
        if (CoreApp::$mode) {
            header('location: /error'); // Redirect to the error page
            return false;
        }

        // Display exception details in development mode
        echo "<b>Exception:</b> " . $exception->getMessage();
    }

    // Destructor

    /**
     * Destructor function to close the database connection.
     * @return void
     */
    public function __destruct() {
        (CoreApp::$db) ? CoreApp::$db->close() : false;
    }
}
