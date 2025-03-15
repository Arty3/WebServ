#!/usr/bin/env python3

import os
import cgi
import cgitb

cgitb.enable()

print("Content-Type: text/html; charset=UTF-8")
print()

print("<html><body>")
print("<h1>Python CGI Test</h1>")

print("<h2>Server Variables:</h2>")
print("<pre>")
for key, value in os.environ.items():
    print(f"{key}: {value}")
print("</pre>")

form = cgi.FieldStorage()

print("<h2>GET Data:</h2>")
print("<pre>")
for key in form.keys():
    if not form[key].filename:
        print(f"{key}: {form.getvalue(key)}")
print("</pre>")

print("<h2>POST Data:</h2>")
print("<pre>")

print("Note: In Python CGI, both GET and POST data are accessible through the same form object.")
print("The data shown above includes both GET and POST parameters.")
print("</pre>")

print("</body></html>")
