<?php

if ( ! defined('BASEPATH')) exit('No direct script access allowed');

abstract class REST extends CI_Controller{

    // Note: Only the widely used HTTP status codes are documented
    // Informational
    const HTTP_CONTINUE = 100;
    const HTTP_SWITCHING_PROTOCOLS = 101;
    const HTTP_PROCESSING = 102;            // RFC2518
    // Success
    const HTTP_OK = 200;
    //The server successfully created a new resource
    const HTTP_CREATED = 201;
    const HTTP_ACCEPTED = 202;
    const HTTP_NON_AUTHORITATIVE_INFORMATION = 203;
    //The server successfully processed the request, though no content is returned
    const HTTP_NO_CONTENT = 204;
    const HTTP_RESET_CONTENT = 205;
    const HTTP_PARTIAL_CONTENT = 206;
    const HTTP_MULTI_STATUS = 207;          // RFC4918
    const HTTP_ALREADY_REPORTED = 208;      // RFC5842
    const HTTP_IM_USED = 226;               // RFC3229
    // Redirection
    const HTTP_MULTIPLE_CHOICES = 300;
    const HTTP_MOVED_PERMANENTLY = 301;
    const HTTP_FOUND = 302;
    const HTTP_SEE_OTHER = 303;
    //The resource has not been modified since the last request
    const HTTP_NOT_MODIFIED = 304;
    const HTTP_USE_PROXY = 305;
    const HTTP_RESERVED = 306;
    const HTTP_TEMPORARY_REDIRECT = 307;
    const HTTP_PERMANENTLY_REDIRECT = 308;  // RFC7238

    // CLIENT ERRORS
    //The request cannot be fulfilled due to multiple errors
    const HTTP_BAD_REQUEST = 400;
    //The user is unauthorized to access the requested resource
    const HTTP_UNAUTHORIZED = 401;
    const HTTP_PAYMENT_REQUIRED = 402;
    //The requested resource is unavailable at this present time
    const HTTP_FORBIDDEN = 403;
    //The requested resources not found
    const HTTP_NOT_FOUND = 404;
    //The request method is not supported by the following resource
    const HTTP_METHOD_NOT_ALLOWED = 405;
    //The request was not acceptable
    const HTTP_NOT_ACCEPTABLE = 406;
    const HTTP_PROXY_AUTHENTICATION_REQUIRED = 407;
    const HTTP_REQUEST_TIMEOUT = 408;
    /**
     * The request could not be completed due to a conflict with the current state
     * of the resource
     */
    const HTTP_CONFLICT = 409;
    const HTTP_GONE = 410;
    const HTTP_LENGTH_REQUIRED = 411;
    const HTTP_PRECONDITION_FAILED = 412;
    const HTTP_REQUEST_ENTITY_TOO_LARGE = 413;
    const HTTP_REQUEST_URI_TOO_LONG = 414;
    const HTTP_UNSUPPORTED_MEDIA_TYPE = 415;
    const HTTP_REQUESTED_RANGE_NOT_SATISFIABLE = 416;
    const HTTP_EXPECTATION_FAILED = 417;
    const HTTP_I_AM_A_TEAPOT = 418;                                               // RFC2324
    const HTTP_UNPROCESSABLE_ENTITY = 422;                                        // RFC4918
    const HTTP_LOCKED = 423;                                                      // RFC4918
    const HTTP_FAILED_DEPENDENCY = 424;                                           // RFC4918
    const HTTP_RESERVED_FOR_WEBDAV_ADVANCED_COLLECTIONS_EXPIRED_PROPOSAL = 425;   // RFC2817
    const HTTP_UPGRADE_REQUIRED = 426;                                            // RFC2817
    const HTTP_PRECONDITION_REQUIRED = 428;                                       // RFC6585
    const HTTP_TOO_MANY_REQUESTS = 429;                                           // RFC6585
    const HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE = 431;                             // RFC6585
    // Server Error
    /**
     * The server encountered an unexpected error
     *
     * Note: This is a generic error message when no specific message
     * is suitable
     */
    const HTTP_INTERNAL_SERVER_ERROR = 500;
    /**
     * The server does not recognise the request method
     */
    const HTTP_NOT_IMPLEMENTED = 501;
    const HTTP_BAD_GATEWAY = 502;
    const HTTP_SERVICE_UNAVAILABLE = 503;
    const HTTP_GATEWAY_TIMEOUT = 504;
    const HTTP_VERSION_NOT_SUPPORTED = 505;
    const HTTP_VARIANT_ALSO_NEGOTIATES_EXPERIMENTAL = 506;                        // RFC2295
    const HTTP_INSUFFICIENT_STORAGE = 507;                                        // RFC4918
    const HTTP_LOOP_DETECTED = 508;                                               // RFC5842
    const HTTP_NOT_EXTENDED = 510;                                                // RFC2774
    const HTTP_NETWORK_AUTHENTICATION_REQUIRED = 511;
    /**
     * This defines the rest format
     * Must be overridden it in a controller so that it is set
     *
     * @var string|NULL
     */
    protected $rest_format = NULL;
    /**
     * Defines the list of method properties such as limit, log and level
     *
     * @var array
     */
    protected $methods = [];
    /**
     * List of allowed HTTP methods
     *
     * @var array
     */
    protected $allowed_http_methods = ['get', 'delete', 'post', 'put'];
    /**
     * Contains details about the request
     * Fields: body, format, method, ssl
     * Note: This is a dynamic object (stdClass)
     *
     * @var object
     */
    protected $request = NULL;
    /**
     * Contains details about the response
     * Fields: format, lang
     * Note: This is a dynamic object (stdClass)
     *
     * @var object
     */
    protected $response = NULL;
    /**
     * Contains details about the REST API
     * Fields: db, ignore_limits, key, level, user_id
     * Note: This is a dynamic object (stdClass)
     *
     * @var object
     */
    protected $rest = NULL;
    /**
     * The arguments for the GET request method
     *
     * @var array
     */
    protected $_get_args = [];
    /**
     * The arguments for the POST request method
     *
     * @var array
     */
    protected $_post_args = [];
    /**
     * The arguments for the PUT request method
     *
     * @var array
     */
    protected $_put_args = [];
    /**
     * The arguments for the DELETE request method
     *
     * @var array
     */
    protected $_delete_args = [];
    /**
     * The arguments for the query parameters
     *
     * @var array
     */
    protected $_query_args = [];
    /**
     * The arguments from GET, POST, PUT, DELETE, PATCH, HEAD and OPTIONS request methods combined
     *
     * @var array
     */
    protected $_args = [];
    /**
     * The insert_id of the log entry (if we have one)
     *
     * @var string
     */
    protected $_insert_id = '';
    /**
     * If the request is allowed based on the API key provided
     *
     * @var bool
     */
    protected $_allow = TRUE;
    /**
     * The start of the response time from the server
     *
     * @var string
     */
    protected $_start_rtime = '';
    /**
     * The end of the response time from the server
     *
     * @var string
     */
    protected $_end_rtime = '';
    /**
     * List all supported methods, the first will be the default format
     *
     * @var array
     */
    protected $_supported_formats = [
        'json' => 'application/json',
        'array' => 'application/json',
        'csv' => 'application/csv',
        'html' => 'text/html',
        'jsonp' => 'application/javascript',
        'php' => 'text/plain',
        'serialized' => 'application/vnd.php.serialized',
        'xml' => 'application/xml'
    ];
    /**
     * HTTP status codes and their respective description
     * Note: Only the widely used HTTP status codes are used
     *
     * @var array
     * @link http://www.restapitutorial.com/httpstatuscodes.html
     */
    protected $http_status_codes = [
        self::HTTP_OK => 'OK',
        self::HTTP_CREATED => 'CREATED',
        self::HTTP_NO_CONTENT => 'NO CONTENT',
        self::HTTP_NOT_MODIFIED => 'NOT MODIFIED',
        self::HTTP_BAD_REQUEST => 'BAD REQUEST',
        self::HTTP_UNAUTHORIZED => 'UNAUTHORIZED',
        self::HTTP_FORBIDDEN => 'FORBIDDEN',
        self::HTTP_NOT_FOUND => 'NOT FOUND',
        self::HTTP_METHOD_NOT_ALLOWED => 'METHOD NOT ALLOWED',
        self::HTTP_NOT_ACCEPTABLE => 'NOT ACCEPTABLE',
        self::HTTP_CONFLICT => 'CONFLICT',
        self::HTTP_INTERNAL_SERVER_ERROR => 'INTERNAL SERVER ERROR',
        self::HTTP_NOT_IMPLEMENTED => 'NOT IMPLEMENTED'
    ];

    function __construct($config = 'rest'){
        parent::__construct();

        // Disable XML Entity (security vulnerability)
        libxml_disable_entity_loader(TRUE);

        // Check to see if PHP is equal to or greater than 5.4.x
        if (is_php('5.4') === FALSE)
        {
            throw new Exception('Using PHP v' . PHP_VERSION . ', though PHP v5.4 or greater is required');
        }

        $this->_enable_xss = ($this->config->item('global_xss_filtering') === TRUE);

        $this->_start_rtime = microtime(TRUE);

        // Load the rest.php configuration file
        $this->load->config($config);

        $this->load->library('format');

        // Determine supported output formats from configuration.
        $supported_formats = $this->config->item('rest_supported_formats');

        // Validate the configuration setting output formats
        if (empty($supported_formats))
        {
            $supported_formats = [];
        }
        if (!is_array($supported_formats))
        {
            $supported_formats = [$supported_formats];
        }

        // Add silently the default output format if it is missing.
        $default_format = $this->get_default_output_format();
        if (!in_array($default_format, $supported_formats))
        {
            $supported_formats[] = $default_format;
        }
        // Now update $this->_supported_formats
        $this->_supported_formats = array_intersect_key($this->_supported_formats, array_flip($supported_formats));

        // Initialise the response, request and rest objects
        $this->request = new stdClass();
        $this->response = new stdClass();
        $this->rest = new stdClass();

        if ($this->config->item('rest_deny_ip_enabled') === TRUE)
        {
            $this->check_deny_ip_auth();
        }

        if ($this->config->item('rest_allowed_ip_enabled') === TRUE)
        {
            $this->check_allowed_ip_auth();
        }

        // Determine whether the connection is HTTPS
        $this->request->ssl = $this->is_https();

        // How is this request being made? GET, POST, DELETE,PUT
        $this->request->method = $this->method();

        if (isset($this->{'_' . $this->request->method . '_args'}) === FALSE)
        {
            $this->{'_' . $this->request->method . '_args'} = [];
        }
        // Set up the query parameters
        $this->parse_query();
        // Set up the GET variables
        $this->_get_args = array_merge($this->_get_args, $this->uri->ruri_to_assoc());
        // Try to find a format for the request (means we have a request body)
        $this->request->format = $this->detect_input_format();
        // Not all methods have a body attached with them
        $this->request->body = NULL;
        $this->{'parse_' . $this->request->method}();
        // Now we know all about our request, let's try and parse the body if it exists
        if ($this->request->format && $this->request->body)
        {
            $this->request->body = $this->format->factory($this->request->body, $this->request->format)->to_array();
            // Assign payload arguments to proper method container
            $this->{'_' . $this->request->method . '_args'} = $this->request->body;
        }
        // Merge both for one mega-args variable
        $this->_args = array_merge(
            $this->_get_args,
            $this->_put_args,
            $this->_post_args,
            $this->_delete_args,
            $this->{'_' . $this->request->method . '_args'}
        );
        // Which format should the data be returned in?
        $this->response->format = $this->detect_output_format();

        // Extend this function to apply additional checking early on in the process
        $this->early_checks();

        if ($this->config->item('rest_database_group') && ($this->config->item('rest_enable_keys') || $this->config->item('rest_enable_logging')))
        {
            $this->rest->db = $this->load->database($this->config->item('rest_database_group'), TRUE);
        }
        // Use whatever database is in use (isset returns FALSE)
        elseif (property_exists($this, 'db'))
        {
            $this->rest->db = $this->db;
        }
        if ($this->config->item('rest_enable_keys'))
        {
            $this->_allow = $this->detect_api_key();
        }

        // Only allow ajax requests
        if ($this->input->is_ajax_request() === FALSE && $this->config->item('rest_ajax_only'))
        {
            // Display an error response
            $this->response([
                $this->config->item('rest_status_field_name') => FALSE,
                $this->config->item('rest_message_field_name') => $this->lang->line('text_rest_ajax_only')
            ], self::HTTP_NOT_ACCEPTABLE);
        }
    }

    public function __destruct(){
        // Get the current timestamp
        $this->_end_rtime = microtime(TRUE);
        // Log the loading time to the log table
        if ($this->config->item('rest_enable_logging') === TRUE)
        {
            $this->log_access_time();
        }
    }

    public function _remap($object_called, $arguments){
        // Should we answer if not over SSL?
        if ($this->config->item('force_https') && $this->request->ssl === FALSE)
        {
            $this->response([
                $this->config->item('rest_status_field_name') => FALSE,
                $this->config->item('rest_message_field_name') => $this->lang->line('text_rest_unsupported')
            ], self::HTTP_FORBIDDEN);
        }
        // Remove the supported format from the function name e.g. index.json => index
        $object_called = preg_replace('/^(.*)\.(?:' . implode('|', array_keys($this->_supported_formats)) . ')$/', '$1', $object_called);
        $controller_method = $this->request->method . '_' . $object_called;
        // Do we want to log this method (if allowed by config)?
        $log_method = !(isset($this->methods[$controller_method]['log']) && $this->methods[$controller_method]['log'] === FALSE);
        // Use keys for this method?
        $use_key = !(isset($this->methods[$controller_method]['key']) && $this->methods[$controller_method]['key'] === FALSE);
        // They provided a key, but it wasn't valid, so get them out of here
        if ($this->config->item('rest_enable_keys') && $use_key && $this->_allow === FALSE)
        {
            if ($this->config->item('rest_enable_logging') && $log_method)
            {
                $this->log_request();
            }
            $this->response([
                $this->config->item('rest_status_field_name') => FALSE,
                $this->config->item('rest_message_field_name') => sprintf($this->lang->line('text_rest_invalid_api_key'), $this->rest->key)
            ], self::HTTP_FORBIDDEN);
        }
        // Check to see if this key has access to the requested controller
        if ($this->config->item('rest_enable_keys') && $use_key && empty($this->rest->key) === FALSE && $this->check_access() === FALSE)
        {
            if ($this->config->item('rest_enable_logging') && $log_method)
            {
                $this->log_request();
            }
            $this->response([
                $this->config->item('rest_status_field_name') => FALSE,
                $this->config->item('rest_message_field_name') => $this->lang->line('text_rest_api_key_unauthorized')
            ], self::HTTP_UNAUTHORIZED);
        }
        // Sure it exists, but can they do anything with it?
        if (method_exists($this, $controller_method) === FALSE)
        {
            $this->response([
                $this->config->item('rest_status_field_name') => FALSE,
                $this->config->item('rest_message_field_name') => $this->lang->line('text_rest_unknown_method')
            ], self::HTTP_NOT_FOUND);
        }
        // Doing key related stuff? Can only do it if they have a key right?
        if ($this->config->item('rest_enable_keys') && empty($this->rest->key) === FALSE)
        {
            // Check the limit
            if ($this->config->item('rest_enable_limits') && $this->check_limit($controller_method) === FALSE)
            {
                $response = [$this->config->item('rest_status_field_name') => FALSE, $this->config->item('rest_message_field_name') => $this->lang->line('text_rest_api_key_time_limit')];
                $this->response($response, self::HTTP_UNAUTHORIZED);
            }
            // If no level is set use 0, they probably aren't using permissions
            $level = isset($this->methods[$controller_method]['level']) ? $this->methods[$controller_method]['level'] : 0;
            // If no level is set, or it is lower than/equal to the key's level
            $authorized = $level <= $this->rest->level;
            // IM TELLIN!
            if ($this->config->item('rest_enable_logging') && $log_method)
            {
                $this->log_request($authorized);
            }
            // They don't have good enough perms
            $response = [$this->config->item('rest_status_field_name') => FALSE, $this->config->item('rest_message_field_name') => $this->lang->line('text_rest_api_key_permissions')];
            $authorized || $this->response($response, self::HTTP_UNAUTHORIZED);
        }
        // No key stuff, but record that stuff is happening
        elseif ($this->config->item('rest_enable_logging') && $log_method)
        {
            $this->log_request($authorized = TRUE);
        }
        // Call the controller method and passed arguments
        try
        {
            call_user_func_array([$this, $controller_method], $arguments);
        }
        catch (Exception $ex)
        {
            // If the method doesn't exist, then the error will be caught and an error response shown
            $this->response([
                $this->config->item('rest_status_field_name') => FALSE,
                $this->config->item('rest_message_field_name') => [
                    'classname' => get_class($ex),
                    'message' => $ex->getMessage()
                ]
            ], self::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    protected function early_checks(){}

    protected function response($data = NULL, $http_code = NULL, $continue = FALSE){
        // If the HTTP status is not NULL, then cast as an integer
        if ($http_code !== NULL)
        {
            // So as to be safe later on in the process
            $http_code = (int) $http_code;
        }
        // Set the output as NULL by default
        $output = NULL;
        // If data is NULL and no HTTP status code provided, then display, error and exit
        if ($data === NULL && $http_code === NULL)
        {
            $http_code = self::HTTP_NOT_FOUND;
        }
        // If data is not NULL and a HTTP status code provided, then continue
        elseif ($data !== NULL)
        {
            // If the format method exists, call and return the output in that format
            if (method_exists($this->format, 'to_' . $this->response->format))
            {
                // Set the format header
                $this->output->set_content_type($this->_supported_formats[$this->response->format], strtolower($this->config->item('charset')));
                $output = $this->format->factory($data)->{'to_' . $this->response->format}();
                // An array must be parsed as a string, so as not to cause an array to string error
                // Json is the most appropriate form for such a datatype
                if ($this->response->format === 'array')
                {
                    $output = $this->format->factory($output)->{'to_json'}();
                }
            }
            else
            {
                // If an array or object, then parse as a json, so as to be a 'string'
                if (is_array($data) || is_object($data))
                {
                    $data = $this->format->factory($data)->{'to_json'}();
                }
                // Format is not supported, so output the raw data as a string
                $output = $data;
            }
        }
        // If not greater than zero, then set the HTTP status code as 200 by default
        // Though perhaps 500 should be set instead, for the developer not passing a
        // correct HTTP status code
        $http_code > 0 || $http_code = self::HTTP_OK;
        $this->output->set_status_header($http_code);
        // JC: Log response code only if rest logging enabled
        if ($this->config->item('rest_enable_logging') === TRUE)
        {
            $this->log_response_code($http_code);
        }
        // Output the data
        $this->output->set_output($output);
        if ($continue === FALSE)
        {
            // Display the data and exit execution
            $this->output->_display();
            exit;
        }
        // Otherwise dump the output automatically
    }

    protected function parse_get(){
        $this->_get_args = array_merge($this->_get_args, $this->_query_args);
    }

    protected function parse_post(){
        $this->_post_args = (count($_POST)>0)?$_POST:file_get_contents('php://input');
        if ($this->request->format)
        {
            $this->request->body = $this->_post_args;
        }
    }

    protected function parse_put(){
        if ($this->method() === 'put')
        {
            $this->request->body = file_get_contents('php://input');
        }
    }

    protected function parse_delete(){
        if ($this->method() === 'delete')
        {
            $this->request->body = file_get_contents('php://input');
        }
    }

    protected function parse_query(){
        $this->_query_args = $this->input->get();
    }

    public function get($key = NULL, $xss_clean = NULL){
        if ($key === NULL){
            return $this->_get_args;
        }
        return isset($this->_get_args[$key]) ? $this->xss_clean($this->_get_args[$key], $xss_clean) : NULL;
    }

    public function post($key = NULL, $xss_clean = NULL){
        if ($key === NULL)
        {
            return $this->_post_args;
        }
        return isset($this->_post_args[$key]) ? $this->xss_clean($this->_post_args[$key], $xss_clean) : NULL;
    }

    public function put($key = NULL, $xss_clean = NULL){
        if ($key === NULL)
        {
            return $this->_put_args;
        }
        return isset($this->_put_args[$key]) ? $this->xss_clean($this->_put_args[$key], $xss_clean) : NULL;
    }

    public function delete($key = NULL, $xss_clean = NULL){
        if ($key === NULL)
        {
            return $this->_delete_args;
        }
        return isset($this->_delete_args[$key]) ? $this->xss_clean($this->_delete_args[$key], $xss_clean) : NULL;
    }

    public function query($key = NULL, $xss_clean = NULL){

    }

    protected function xss_clean($value, $xss_clean){
        is_bool($xss_clean) || $xss_clean = $this->_enable_xss;
        return $xss_clean === TRUE ? $this->security->xss_clean($value) : $value;
    }

    public function validation_errors(){
        $string = strip_tags($this->form_validation->error_string());
        return explode(PHP_EOL, trim($string, PHP_EOL));
    }

    public function set_response($data = NULL, $http_code = NULL){
        $this->response($data, $http_code, TRUE);
    }

    protected function log_access_time(){
        $payload['rtime'] = $this->_end_rtime - $this->_start_rtime;
        return $this->rest->db->update(
            $this->config->item('rest_logs_table'), $payload, [
            'id' => $this->_insert_id
        ]);
    }

    protected function log_response_code($http_code){
        $payload['response_code'] = $http_code;
        return $this->rest->db->update(
            $this->config->item('rest_logs_table'), $payload, [
            'id' => $this->_insert_id
        ]);
    }

    protected function detect_input_format(){
        // Get the CONTENT-TYPE value from the SERVER variable
        $content_type = $this->input->server('CONTENT_TYPE');
        if (empty($content_type) === FALSE)
        {
            // Check all formats against the HTTP_ACCEPT header
            foreach ($this->_supported_formats as $key => $value)
            {
                // $key = format e.g. csv
                // $value = mime type e.g. application/csv
                // If a semi-colon exists in the string, then explode by ; and get the value of where
                // the current array pointer resides. This will generally be the first element of the array
                $content_type = (strpos($content_type, ';') !== FALSE ? current(explode(';', $content_type)) : $content_type);
                // If both the mime types match, then return the format
                if ($content_type === $value)
                {
                    return $key;
                }
            }
        }
        return NULL;
    }

    protected function get_default_output_format(){
        $default_format = (string) $this->config->item('rest_default_format');
        return $default_format === '' ? 'json' : $default_format;
    }

    protected function detect_output_format(){
        // Concatenate formats to a regex pattern e.g. \.(csv|json|xml)
        $pattern = '/\.(' . implode('|', array_keys($this->_supported_formats)) . ')($|\/)/';
        $matches = [];
        // Check if a file extension is used e.g. http://example.com/api/index.json?param1=param2
        if (preg_match($pattern, $this->uri->uri_string(), $matches))
        {
            return $matches[1];
        }
        // Get the format parameter named as 'format'
        if (isset($this->_get_args['format']))
        {
            $format = strtolower($this->_get_args['format']);
            if (isset($this->_supported_formats[$format]) === TRUE)
            {
                return $format;
            }
        }
        // Get the HTTP_ACCEPT server variable
        $http_accept = $this->input->server('HTTP_ACCEPT');
        // Otherwise, check the HTTP_ACCEPT server variable
        if ($this->config->item('rest_ignore_http_accept') === FALSE && $http_accept !== NULL)
        {
            // Check all formats against the HTTP_ACCEPT header
            foreach (array_keys($this->_supported_formats) as $format)
            {
                // Has this format been requested?
                if (strpos($http_accept, $format) !== FALSE)
                {
                    if ($format !== 'html' && $format !== 'xml')
                    {
                        // If not HTML or XML assume it's correct
                        return $format;
                    }
                    elseif ($format === 'html' && strpos($http_accept, 'xml') === FALSE)
                    {
                        // HTML or XML have shown up as a match
                        // If it is truly HTML, it wont want any XML
                        return $format;
                    }
                    else if ($format === 'xml' && strpos($http_accept, 'html') === FALSE)
                    {
                        // If it is truly XML, it wont want any HTML
                        return $format;
                    }
                }
            }
        }
        // Check if the controller has a default format
        if (empty($this->rest_format) === FALSE)
        {
            return $this->rest_format;
        }
        // Obtain the default format from the configuration
        return $this->get_default_output_format();
    }

    protected function detect_method(){
        // Get the request method as a lowercase string
        $method = $this->method();
        return in_array($method, $this->allowed_http_methods) && method_exists($this, 'parse_' . $method) ? $method : 'get';
    }

    function http_response_code($code = NULL) {

        if ($code !== NULL) {

            switch ($code) {
                case 100: $text = 'Continue'; break;
                case 101: $text = 'Switching Protocols'; break;
                case 200: $text = 'OK'; break;
                case 201: $text = 'Created'; break;
                case 202: $text = 'Accepted'; break;
                case 203: $text = 'Non-Authoritative Information'; break;
                case 204: $text = 'No Content'; break;
                case 205: $text = 'Reset Content'; break;
                case 206: $text = 'Partial Content'; break;
                case 300: $text = 'Multiple Choices'; break;
                case 301: $text = 'Moved Permanently'; break;
                case 302: $text = 'Moved Temporarily'; break;
                case 303: $text = 'See Other'; break;
                case 304: $text = 'Not Modified'; break;
                case 305: $text = 'Use Proxy'; break;
                case 400: $text = 'Bad Request'; break;
                case 401: $text = 'Unauthorized'; break;
                case 402: $text = 'Payment Required'; break;
                case 403: $text = 'Forbidden'; break;
                case 404: $text = 'Not Found'; break;
                case 405: $text = 'Method Not Allowed'; break;
                case 406: $text = 'Not Acceptable'; break;
                case 407: $text = 'Proxy Authentication Required'; break;
                case 408: $text = 'Request Time-out'; break;
                case 409: $text = 'Conflict'; break;
                case 410: $text = 'Gone'; break;
                case 411: $text = 'Length Required'; break;
                case 412: $text = 'Precondition Failed'; break;
                case 413: $text = 'Request Entity Too Large'; break;
                case 414: $text = 'Request-URI Too Large'; break;
                case 415: $text = 'Unsupported Media Type'; break;
                case 500: $text = 'Internal Server Error'; break;
                case 501: $text = 'Not Implemented'; break;
                case 502: $text = 'Bad Gateway'; break;
                case 503: $text = 'Service Unavailable'; break;
                case 504: $text = 'Gateway Time-out'; break;
                case 505: $text = 'HTTP Version not supported'; break;
                default:
                    exit('Unknown http status code "' . htmlentities($code) . '"');
                    break;
            }

            $protocol = (isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0');

            header($protocol . ' ' . $code . ' ' . $text);

            $GLOBALS['http_response_code'] = $code;

        } else {

            $code = (isset($GLOBALS['http_response_code']) ? $GLOBALS['http_response_code'] : 200);

        }

        return $code;

    }

    protected function log_request($authorized = FALSE){
        // Insert the request into the log table
        $is_inserted = $this->rest->db
            ->insert(
                $this->config->item('rest_logs_table'), [
                'uri' => $this->uri->uri_string(),
                'method' => $this->request->method,
                'params' => $this->_args ? ($this->config->item('rest_logs_json_params') === TRUE ? json_encode($this->_args) : serialize($this->_args)) : NULL,
                'api_key' => isset($this->rest->key) ? $this->rest->key : '',
                'ip_address' => $this->input->ip_address(),
                'time' => time(),
                'authorized' => $authorized
            ]);
        // Get the last insert id to update at a later stage of the request
        $this->_insert_id = $this->rest->db->insert_id();
        return $is_inserted;
    }

    function is_https(){
        if ( ! empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off'){
            return TRUE;
        }
        elseif (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https'){
            return TRUE;
        }
        elseif ( ! empty($_SERVER['HTTP_FRONT_END_HTTPS']) && strtolower($_SERVER['HTTP_FRONT_END_HTTPS']) !== 'off'){
            return TRUE;
        }
        return FALSE;
    }

    function method(){
        return (isset($_SERVER['REQUEST_METHOD'])) ? strtolower($_SERVER['REQUEST_METHOD']) : 'get';
    }

    /**
     * Check to see if the API key has access to the controller and methods
     *
     * @access protected
     * @return bool TRUE the API key has access; otherwise, FALSE
     */
    protected function check_access()
    {
        // If we don't want to check access, just return TRUE
        if ($this->config->item('rest_enable_access') === FALSE)
        {
            return TRUE;
        }
        // Fetch controller based on path and controller name
        $controller = implode(
            '/', [
            $this->router->directory,
            $this->router->class
        ]);
        // Remove any double slashes for safety
        $controller = str_replace('//', '/', $controller);
        // Query the access table and get the number of results
        return $this->rest->db
            ->where('key', $this->rest->key)
            ->where('controller', $controller)
            ->get($this->config->item('rest_access_table'))
            ->num_rows() > 0;
    }

    /**
     * Check if the requests to a controller method exceed a limit
     *
     * @access protected
     * @param  string $controller_method The method being called
     * @return bool TRUE the call limit is below the threshold; otherwise, FALSE
     */
    protected function check_limit($controller_method)
    {
        // They are special, or it might not even have a limit
        if (empty($this->rest->ignore_limits) === FALSE)
        {
            // Everything is fine
            return TRUE;
        }
        switch ($this->config->item('rest_limits_method'))
        {
            case 'API_KEY':
                $limited_uri = 'api-key:' . (isset($this->rest->key) ? $this->rest->key : '');
                $limited_method_name = isset($this->rest->key) ? $this->rest->key : '';
                break;
            case 'METHOD_NAME':
                $limited_uri = 'method-name:' . $controller_method;
                $limited_method_name =  $controller_method;
                break;
            case 'ROUTED_URL':
            default:
                $limited_uri = $this->uri->ruri_string();
                if (strpos(strrev($limited_uri), strrev($this->response->format)) === 0)
                {
                    $limited_uri = substr($limited_uri,0, -strlen($this->response->format) - 1);
                }
                $limited_uri = 'uri:' . $limited_uri . ':' . $this->request->method; // It's good to differentiate GET from PUT
                $limited_method_name = $controller_method;
                break;
        }
        if (isset($this->methods[$limited_method_name]['limit']) === FALSE )
        {
            // Everything is fine
            return TRUE;
        }
        // How many times can you get to this method in a defined time_limit (default: 1 hour)?
        $limit = $this->methods[$limited_method_name]['limit'];
        $time_limit = (isset($this->methods[$limited_method_name]['time']) ? $this->methods[$limited_method_name]['time'] : 3600); // 3600 = 60 * 60
        // Get data about a keys' usage and limit to one row
        $result = $this->rest->db
            ->where('uri', $limited_uri)
            ->where('api_key', $this->rest->key)
            ->get($this->config->item('rest_limits_table'))
            ->row();
        // No calls have been made for this key
        if ($result === NULL)
        {
            // Create a new row for the following key
            $this->rest->db->insert($this->config->item('rest_limits_table'), [
                'uri' => $limited_uri,
                'api_key' => isset($this->rest->key) ? $this->rest->key : '',
                'count' => 1,
                'hour_started' => time()
            ]);
        }
        // Been a time limit (or by default an hour) since they called
        elseif ($result->hour_started < (time() - $time_limit))
        {
            // Reset the started period and count
            $this->rest->db
                ->where('uri', $limited_uri)
                ->where('api_key', isset($this->rest->key) ? $this->rest->key : '')
                ->set('hour_started', time())
                ->set('count', 1)
                ->update($this->config->item('rest_limits_table'));
        }
        // They have called within the hour, so lets update
        else
        {
            // The limit has been exceeded
            if ($result->count >= $limit)
            {
                return FALSE;
            }
            // Increase the count by one
            $this->rest->db
                ->where('uri', $limited_uri)
                ->where('api_key', $this->rest->key)
                ->set('count', 'count + 1', FALSE)
                ->update($this->config->item('rest_limits_table'));
        }
        return TRUE;
    }

    /**
     * Checks if the client's ip is in the 'rest_deny_ip' config and generates a 401 response
     *
     * @access protected
     * @return void
     */
    protected function check_deny_ip_auth()
    {
        // Match an ip address in a denied ips e.g. 127.0.0.0, 0.0.0.0

        if (in_array($this->input->ip_address(), $this->config->item('rest_deny_ip')))
        {
            // Display an error response
            $this->response([
                $this->config->item('rest_status_field_name') => FALSE,
                $this->config->item('rest_message_field_name') => $this->lang->line('text_rest_ip_denied')
            ], self::HTTP_UNAUTHORIZED);
        }
    }
    /**
     * Check if the client's ip is in the 'rest_allowed_ip' config and generates a 401 response
     *
     * @access protected
     * @return void
     */
    protected function check_allowed_ip_auth()
    {
        $allowed_ips = $this->config->item('rest_allowed_ip');
        array_push($allowed_ips, '127.0.0.1', '0.0.0.0');
        if (in_array($this->input->ip_address(), array_map('trim',$allowed_ips)) === FALSE)
        {
            $this->response([
                $this->config->item('rest_status_field_name') => FALSE,
                $this->config->item('rest_message_field_name') => $this->lang->line('text_rest_ip_unauthorized')
            ], self::HTTP_UNAUTHORIZED);
        }
    }

    /**
     * See if the user has provided an API key
     *
     * @access protected
     * @return bool
     */
    protected function detect_api_key()
    {
        // Get the api key name variable set in the rest config file
        $api_key_variable = $this->config->item('rest_key_name');
        // Work out the name of the SERVER entry based on config
        $key_name = 'HTTP_' . strtoupper(str_replace('-', '_', $api_key_variable));
        $this->rest->key = NULL;
        $this->rest->level = NULL;
        $this->rest->user_id = NULL;
        $this->rest->ignore_limits = FALSE;
        // Find the key from server or arguments
        if (($key = isset($this->_args[$api_key_variable]) ? $this->_args[$api_key_variable] : $this->input->server($key_name)))
        {
            if (!($row = $this->rest->db->where($this->config->item('rest_key_column'), $key)->get($this->config->item('rest_keys_table'))->row()))
            {
                return FALSE;
            }
            $this->rest->key = $row->{$this->config->item('rest_key_column')};
            isset($row->user_id) && $this->rest->user_id = $row->user_id;
            isset($row->level) && $this->rest->level = $row->level;
            isset($row->ignore_limits) && $this->rest->ignore_limits = $row->ignore_limits;
            $this->_apiuser = $row;
            /*
             * If "is private key" is enabled, compare the ip address with the list
             * of valid ip addresses stored in the database
             */
            if (empty($row->is_private_key) === FALSE)
            {
                // Check for a list of valid ip addresses
                if (isset($row->ip_addresses))
                {
                    // multiple ip addresses must be separated using a comma, explode and loop
                    $list_ip_addresses = explode(',', $row->ip_addresses);
                    $found_address = FALSE;
                    foreach ($list_ip_addresses as $ip_address)
                    {
                        if ($this->input->ip_address() === trim($ip_address))
                        {
                            // there is a match, set the the value to TRUE and break out of the loop
                            $found_address = TRUE;
                            break;
                        }
                    }
                    return $found_address;
                }
                else
                {
                    // There should be at least one IP address for this private key
                    return FALSE;
                }
            }
            return TRUE;
        }
        // No key has been sent
        return FALSE;
    }
}