<?php
include('admin/includes/security.php');

if (!isset($_POST['username'], $_POST['email'], $_POST['password'])) {
	// Could not get the data that should have been sent.
	exit('Please complete the registration form!');
}
	
if (empty($_POST['username']) || empty($_POST['email'])|| empty($_POST['password']) ) {
	// One or more values are empty.
	exit('Please complete the registration form');
}

if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
	exit('Email is not valid!');
}

if (preg_match('/^[a-zA-Z0-9]+$/', $_POST['username']) == 0) {
    exit('Username is not valid!');
}

if (strlen($_POST['password']) > 20 || strlen($_POST['password']) < 5) {
	exit('Password must be between 5 and 20 characters long!');
}
if($_SERVER["REQUEST_METHOD"]=="POST" && isset($_POST['submit']))
{
	$username = trim($_POST['username']);
	$password = trim($_POST['password']);
	$password_hash= password_hash($password,PASSWORD_BCRYPT);
}

if ($stmt = $connection->prepare('SELECT id,password FROM voters WHERE username = ?'))
{
	$stmt->bind_param('s', $_POST['username']);
	$stmt->execute();
	$stmt->store_result();
	
	if ($stmt->num_rows > 0) 
	{
		// Username already exists
		echo 'Username exists, please choose another!';
	}
	else {
		if ($stmt = $connection->prepare('INSERT INTO voters(username, email,password) VALUES (?, ?, ?)'))
			{
	// We do not want to expose passwords in our database, so hash the password and use password_verify when a user logs in.
	
	$password = password_hash($_POST['password'], PASSWORD_DEFAULT);
	$stmt->bind_param('sss', $_POST['username'], $_POST['email'], $password);
	$stmt->execute();

	header("location:register_Success.html");
 } else {

	echo 'Could not !';
	}
 }
  }else{
	echo ' prepare statement!';
      }$stmt->close();
$con->close();
?>

