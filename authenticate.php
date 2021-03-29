<?php
include('admin/includes/security.php');

if ( !isset($_POST['username'], $_POST['password']) ) 
{
	// Could not get the data that should have been sent.
	exit('Please fill both the username and password fields!');
}

if ($stmt = $connection->prepare('SELECT id, password FROM voters WHERE username = ?')) 
{
	$stmt->bind_param('s', $_POST['username']);
	$stmt->execute();
	$stmt->store_result();

    if ($stmt->num_rows > 0) 
    {
        $stmt->bind_result($id, $password);
        $stmt->fetch();
        // Account exists, now we verify the password.
        // Note: remember to use password_hash in your registration file to store the hashed passwords.
        if (password_verify($_POST['password'], $password)) 
        {
            // Verification success! User has logged-in!
            // Create sessions, so we know the user is logged in, they basically act like cookies but remember the data on the server.
            session_regenerate_id();
            $_SESSION['loggedin'] = TRUE;
            $_SESSION['name'] = $_POST['username'];
            $_SESSION['id'] = $id;

           echo 'Welcome ' . $_SESSION['name'] . '.';
            echo '<p>This page is currently under construction!!!</p>';
        } else {
            // Incorrect password
            echo 'Incorrect password!';
        }
    } 
    
    else {
        if ($query = $connection->prepare('SELECT admin_id, password FROM admin WHERE username = ?')) 
{
	$query->bind_param('s', $_POST['username']);
	$query->execute();
	$query->store_result();

    if ($query->num_rows > 0) {
        $query->bind_result($id, $password);
        $query->fetch();
        // Account exists, now we verify the password.
        // Note: remember to use password_hash in your registration file to store the hashed passwords.
        if ($_POST['password'] === $password) 
        {
            // Verification success! User has logged-in!
            // Create sessions, so we know the user is logged in, they basically act like cookies but remember the data on the server.
            session_regenerate_id();
            $_SESSION['loggedin'] = TRUE;
            $_SESSION['name'] = $_POST['username'];
            $_SESSION['admin_id'] = $id;
            header("location:admin/index.php");
        } else {
            // Incorrect password
            echo 'Incorrect  password!';
        }
    } else {
        // Incorrect username
        echo 'Incorrect username!';
    }

	$query->close();
}
    }

	$stmt->close();
}


?>