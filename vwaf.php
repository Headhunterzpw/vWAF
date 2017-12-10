<?php

/**
* Name - vWAF
* Alias - Vuln-WAF, Virtual-WAF
* @author Alex
* @version 1.0
*/

class vWAF
{
	
	function __construct()
	{
		
		$this->RemoteIP = 'REMOTE_ADDR';

	}

	function CloudFlare()
	{

		$this->RemoteIP = 'HTTP_CF_CONNECTING_IP';

	}

	function BlazingFast()
	{

		$this->RemoteIP = 'X-Real-IP';

	}

	function vblock($rmethod, $vulntype, $badvar)
	{

		die('

			<!DOCTYPE html>

			<html>

				<head>
					
					<title>vWAF</title>
					<meta http-equiv="content-type" content="text/html; charset=UTF-8">
					<meta name="viewport" content="width=device-width, initial-scale=1.0">

					<style>

						.vtable
						{

							width: 100%;

						}

						.alert
						{

							font-family: Trebuchet MS;
							color: white;
							background-color: red;
							text-align: center;
							font-size: 30px;

						}

						p
						{

							font-family: Helvetica;

						}

						.why
						{

							font-size: 20px;

						}

						.version
						{

							position: absolute;
							right: 0;
							bottom: 0;
							left: 0;
							padding: 1rem;
							background-color: #efefef;
							text-align: center;

						}

					</style>

				</head>

				<body>

					<table class="vtable">

						<tbody>

							<tr>

								<td class="alert"><b>Request blocked</b></td>

							</tr>

						</tbody>

					</table>

					<br>

					<center>

						<b>

								<p class="why">vWAF detected something unusual, and decided to block the request for security purposes.</p>

						</b>

					</center>

					<br>

					<hr>

					<p>Request Method : <b>'.$rmethod.'</b></p>
					<p>String Detected : <b>'.htmlentities($badvar).'</b></p>
					<p>Type : <b>'.$vulntype.'</b></p>
					<p>Remote IP Address : <b>'.$_SERVER[$this->RemoteIP].'</b></p>

					<hr>

					<p><small>If you have any problems open a issue <a href="https://github.com/AlexG0D/vWAF/issues/new">here.</a></small></p>

					<p class="version"><b>vWAF - 1.0</b></p>

				</body>

			</html>

			');

	}

	function html($string)
	{

		return preg_match("/<[^<]+>/", $string, $m) != 0;

	}

	function vulnArray($type)
	{

		switch($type)
		{

			case 'SQL' :

				return array(
								"'",
								"SET",
								"SELECT FROM",
								"SELECT * FROM",
								"0x3c696d67207372633d22",
								"0x3c62723e3c62723e3c62723e",
								"concat(0x",
								"union(((((((",
								"mid((select",
								"0x50",
								"table",
								"drop",
								"WHERE ",
								"UPDATE ",
								"UNION",
								"ONION",
								"+#1q%0AuNiOn all#qa%0A#%0AsEleCt",
								"unhex(hex(Concat(",
								"Table_schema,0x3e"
							);
				break;

			case 'XSS' :

				return array(
								"document.cookie",
								"<script",
								"/script>",
								"<img",
								"/img>",
								"<iframe",
								"/iframe>",
								"onerror=",
								"onerror(",
								"svg onload=",
								"svg onload(",
								"body onload=",
								"body onload(",
								"onmouseover=",
								"onmouseover(",
								"javascript:;",
								"javascript:0;",
								"alert(",
								");",
								"String.fromCharCode("
							);
				break;

			case 'HTML' :

				return array(
								"<",
								"%27",
								"&",
								";",
								"#"
							);
				break;

			default :

				return false;
				break;

		}

	}

	function html_check($var, $method)
	{

		if($this->html(strtolower($var)) !== false)
		{

			$this->vblock($method, "HTML Characters", $var);

		}
		else
		{

			$vulnlist = $this->vulnArray('HTML');

			foreach($vulnlist as $vuln)
			{

				if(strpos(strtolower($var), strtolower($vuln)) !== false)
				{

					$this->vblock($method, "HTML Characters", $var);

				}

			}

		}

	}

	function sql_check($var, $method)
	{

		$replacement = array(
								"can't" => "cant",
								"don't" => "dont"
							);
		foreach ($replacement as $old => $new)
		{
			
			$var = str_replace($old, $new, $var);

		}

		$vulnlist = $this->vulnArray('SQL');

		foreach($vulnlist as $vuln)
		{

			if(strpos(strtolower($var), strtolower($vuln)) !== false)
			{

					$this->vblock($method, "SQLi", $var);

			}

		}

	}

	function xss_check($var, $method)
	{

		$replacement = array(
								"<3" => "heart"
							);
		foreach ($replacement as $old => $new)
		{
			
			$var = str_replace($old, $new, $var);

		}

		$vulnlist = $this->vulnArray('XSS');

		foreach($vulnlist as $vuln)
		{

			if(strpos(strtolower($var), strtolower($vuln)) !== false)
			{

					$this->vblock($method, "XSS", $var);

			}

		}

	}

	function Validate_GET()
	{

		foreach($_GET as $key => $value)
		{

			$this->sql_check($value, "GET");
			$this->xss_check($value, "GET");
			$this->html_check($value, "GET");

		}

	}

	function Validate_POST()
	{

		foreach($_POST as $key => $value)
		{

			$this->sql_check($value, "POST");
			$this->xss_check($value, "POST");
			$this->html_check($value, "POST");

		}

	}

	function Validate_COOKIE()
	{

		foreach($_COOKIE as $key => $value)
		{

			$this->sql_check($value, "COOKIE");
			$this->xss_check($value, "COOKIE");
			$this->html_check($value, "COOKIE");

		}

	}

	function init()
	{

		$this->Validate_GET();
		$this->Validate_POST();
		$this->Validate_COOKIE();
	}


}

?>
