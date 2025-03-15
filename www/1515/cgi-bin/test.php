<?php
header("Content-Type: text/html; charset=UTF-8");

echo "<html><body>";
echo "<h1>PHP CGI Test</h1>";

echo "<h2>Server Variables:</h2>";
echo "<pre>";
foreach ($_SERVER as $key => $value) {
    echo htmlspecialchars("$key: $value\n");
}
echo "</pre>";

echo "<h2>GET Data:</h2>";
echo "<pre>";
print_r($_GET);
echo "</pre>";

echo "<h2>POST Data:</h2>";
echo "<pre>";
print_r($_POST);
echo "</pre>";

echo "</body></html>";
?>