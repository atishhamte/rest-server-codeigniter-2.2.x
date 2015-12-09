# CodeIgniter Rest Server

A fully RESTful server implementation for CodeIgniter using one library, one
config file and one controller.

## Requirements

1. PHP 5.4 or greater
2. CodeIgniter 2.0+

## Installation

Drag and drop the **application/libraries/Format.php** and **application/libraries/Rest.php** files into your application's directories. To use `require_once` it at the top of your controllers to load it into the scope. Additionally, copy the **rest.php** file from **application/config** in your application's configuration directory.

## Handling Requests

When your controller extends from `Rest`, the method names will be appended with the HTTP method used to access the request. If you're  making an HTTP `GET` call to `/books`, for instance, it would call a `Books#index_get()` method.

This allows you to implement a RESTful interface easily:

```php
class Books extends Rest
{
  public function get_index()
  {
    // Display all books
  }

  public function post_index()
  {
    // Create a new book
  }
}
```

`Rest` also supports `PUT` and `DELETE` methods, allowing you to support a truly RESTful interface.


Accessing parameters is also easy. Simply use the name of the HTTP verb as a method:

```php
$this->get('blah'); // GET param
$this->post('blah'); // POST param
$this->put('blah'); // PUT param
```

The HTTP spec for DELETE requests precludes the use of parameters.  For delete requests, you can add items to the URL

```php
public function index_delete($id)
{
	$this->response([
		'returned from delete:' => $id,
	]);
}
```

If query parameters are passed via the URL, regardless of whether it's a GET request, can be obtained by the query method:

```php
$this->query('blah'); // Query param
```

## Content Types

`Rest` supports a bunch of different request/response formats, including XML, JSON and serialised PHP. By default, the class will check the URL and look for a format either as an extension or as a separate segment.

This means your URLs can look like this:
```
http://example.com/books.json
http://example.com/books?format=json
```

This can be flaky with URI segments, so the recommend approach is using the HTTP `Accept` header:

```bash
$ curl -H "Accept: application/json" http://example.com
```

Any responses you make from the class (see [responses](#responses) for more on this) will be serialised in the designated format.

## Responses

The class provides a `response()` method that allows you to return data in the user's requested response format.

Returning any object / array / string / whatever is easy:

```php
public function index_get()
{
  $this->response($this->db->get('books')->result());
}
```

This will automatically return an `HTTP 200 OK` response. You can specify the status code in the second parameter:

```php
public function index_post()
  {
    // ...create new book
    $this->response($book, 201); // Send an HTTP 201 Created
  }
```

If you don't specify a response code, and the data you respond with `== FALSE` (an empty array or string, for instance), the response code will automatically be set to `404 Not Found`:

```php
$this->response([]); // HTTP 404 Not Found
```

## Authentication

If you enable `$config['rest_ip_whitelist_enabled']` in your config file, you can then set a list of allowed IPs.

Any client connecting to your API will be checked against the whitelisted IP array. If they're on the list, they'll be allowed access. If not, sorry, no can do hombre. The whitelist is a comma-separated string:

```php
$config['rest_ip_whitelist'] = '123.456.789.0, 987.654.32.1';
```

Your localhost IPs (`127.0.0.1` and `0.0.0.0`) are allowed by default.

## API Keys

In addition to the authentication methods above, the `Rest` class also supports the use of API keys. Enabling API keys is easy. Turn it on in your **config/rest.php** file:

```php
$config['rest_enable_keys'] = TRUE;
```

You'll need to create a new database table to store and access the keys. `Rest` will automatically assume you have a table that looks like this:

```sql
CREATE TABLE `keys` (
	`id` INT(11) NOT NULL AUTO_INCREMENT,
	`key` VARCHAR(40) NOT NULL,
	`level` INT(2) NOT NULL,
	`ignore_limits` TINYINT(1) NOT NULL DEFAULT '0',
	`date_created` INT(11) NOT NULL,
	PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```

The class will look for an HTTP header with the API key on each request. An invalid or missing API key will result in an `HTTP 403 Forbidden`.

By default, the HTTP will be `X-API-KEY`. This can be configured in **config/rest.php**.

```bash
$ curl -X POST -H "X-API-KEY: some_key_here" http://example.com/books
```
