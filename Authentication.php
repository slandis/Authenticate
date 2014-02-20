<?php
/*
 * Authenticate - Authentication.php
 * Copyright (C) 2014 Shaun Landis
 * slandis@gmail.com
 * https://github.com/slandis/Authenticate
 *
 * A relatively simple authentication theme for php+sqlite.
 *
 * Portions of this codebase are taken/modified from:
 * https://github.com/Pomax/Usered - Copyright (C) 2011 Mike Kamermans
 * and as such this work is distributed under the same "MIT (Expat)" license.
 *
 * Please see LICENSE file.
 */

class Authentication {
	private $database = false;

	/* Add specific roles in between ROLE_ADMIN and ROLE_USER */
	const ROLE_ADMIN	= 1;
	const ROLE_USER		= 32;

	public function __construct($dsn) {
		$this->database = new PDO('sqlite:' . $dsn);
	}

	public function addUser($username, $password, $email, $first, $last, $role) {
		$timeout = 0;
		$token = $this->generateAuthenticationToken();
		$hash = hash('sha256', $username . $password . $token);

		$s = 'INSERT INTO users(username,email,first,last,role,hash,token,timeout) VALUES(:username,:email,:first,:last,:role,:hash,:token,:timeout)';
		$q = $this->database->prepare($s);
		$q->bindValue(':username', $username);
		$q->bindValue(':email', $email);
		$q->bindValue(':first', $first);
		$q->bindValue(':last', $last);
		$q->bindValue(':role', $role);
		$q->bindValue(':hash', $hash);
		$q->bindValue(':token', $token);
		$q->bindValue(':timeout', $timeout);

		if (!$q->execute()) {
			return false;
		}

		/* Add your own mailing function here */

		return true;
	}

	public function removeUser($username) {
		$s = 'DELETE FROM users WHERE username=:username';
		$q = $this->database->prepare($s);
		$q->bindValue(':username', $username);

		if (!$q->execute()) {
			return false;
		}

		return true;
	}

	public function resetPassword($username) {
		$ascii = "0a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6A7B8C9D0E1F2G3H4I5J6K7L8M9N0O1P2Q3R4S5T6U7V8W9X0Y1Z23456789";

		$s = 'SELET email,token FROM users WHERE username=:username';
		$q = $this->database->prepare($s);
		$q->bindValue(':username', $username);

		if (!$q->execute()) {
			return false;
		}

		$r = $q->fetchObject();
		$email = $r->email;
		$token = $r->token;

		$string = "";
		$max = strlen($ascii) - 1;
		$length = 64;

		while ($length-- > 0) {
			$string .= $acsii[mt_rand(0, $max)];
		}

		$s = 'UPDATE users SET hash=:hash WHERE username=:username';
		$q = $this->database->prepare($s);
		$q->bindValue(':hash', hash('sha256', $username . $string . $token));
		$q->bindValue(':username', $username);

		if (!$q->execute()) {
			return false;
		}

		/* Add your own mailing function here */
	}

	public function validateEmail($email) {
		$emailregexp = "/[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/";

		if (!preg_match($emailregexp, $email)) {
			return false;
		}

		return true;
	}

	public function validateUsername(&$username) {
		if (!preg_match('/[[:word:]]{6,}/', $username)) {
			return false;
		}

		if (strlen($username) > 32) {
			$username = substr($username, 0, 32);
		}

		return true;
	}

	public function generateAuthenticationToken($length = 32) {
		$hex = "0123456789abcdef";
		$string = "";
		$max = strlen($hex)-1;

		while($length-- > 0) {
			$string .= $hex[mt_rand(0, $max)];
		}
		
		return $string;
	}
}
?>
