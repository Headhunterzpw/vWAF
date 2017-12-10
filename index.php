<?php

session_start();

require('vwaf.php'); // Before everything, very important, include the class.

$vWAF = new vWAF(); // Define a var for the class.
$vWAF->init(); // Check all GET, POST & COOKIE's values and block if a malicious is detected.

if(isset($_POST['vwafvalidate']))
{


	$exampleinput = $_POST['vwafinput'];

	if(empty($exampleinput))
	{

		$error['bad'] = 'Please fill in all fields.';

	}
	else
	{

		//  | Validate the POST input.
		// \/

		$vWAF->sql_check($exampleinput, $_SERVER['REQUEST_METHOD']);
		$vWAF->xss_check($exampleinput, $_SERVER['REQUEST_METHOD']);
		$vWAF->html_check($exampleinput, $_SERVER['REQUEST_METHOD']);

		// If the input passed the check's its safe.

		$success['good'] = 'String : <u>'.$exampleinput.'</u> passed the check\'s.';

	}

}

?>

<!DOCTYPE html>

<html>

	<head>

		<title>vWAF - Example</title>
		<meta http-equiv="content-type" content="text/html; charset=UTF-8">
		<link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet">

	</head>

	<body>

		<div class="container">

			<br>
			<br>
			<br>
			<br>
			<br>

			<center>

				<h1><b>vWAF</b> - Validate a POST form.</h1>

				<?php if(isset($success))
				{

					?>
					
					<div class="alert alert-success" role="alert">

						<ul>

						<?php

						foreach ($success as $goodmsg)
						{
							?>
							<li><b><?php echo $goodmsg; ?></b></li>
							<?php
						}

						?>

						</ul>

					</div>

					<?php

				}

				?>

				<?php if(isset($error))
				{

					?>
					
					<div class="alert alert-danger" role="alert">

						<ul>

						<?php

						foreach ($error as $badmsg)
						{
							?>
							<li><b><?php echo $badmsg; ?></b></li>
							<?php
						}

						?>

						</ul>

					</div>

					<?php

				}

				?>

				<form method="POST">

					<div class="form-group">

						<input type="text" class="form-control" name="vwafinput" placeholder="vWAF - Example input">

					</div>

					<div class="form-group">

						<button class="btn btn-success" name="vwafvalidate">Validate POST form</button>

					</div>

				</form>

			</center>

		</div>

	</body>

</html>
