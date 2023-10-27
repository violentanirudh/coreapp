# CoreApp

```
Just download CoreApp.php from GitHub and start building simple applications within hours.

-----
Directory Structure
-----

public /
|- assets /
|- templates /
|- CoreApp.php
|- index.php
```

## URL Rewriting

```nginx
# APACHE .htaccess

RewriteEngine on
RewriteCond %{REQUEST_FILENAME} !-d
RewriteCond %{REQUEST_FILENAME} !-f
RewriteRule . index.php [L]

# NGINX nginx.conf

try_files $uri /index.php;
```

## Basic Application

Building a minimal routes using CoreApp

```php
<?php

require __DIR__ . '/CoreApp.php';

// Creating App

$app = new CoreApp();

// Functions

function home() {
    echo "Hello, World!";
}

function blog($id) {
    echo "Hello, World! Blog : $id";
}

// Adding routes

$app -> add('GET', '/', 'home');
$app -> add('GET', '/blog/:id', 'blog');

$app -> run();
```

