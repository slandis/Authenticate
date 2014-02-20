<?php
/*
 * Authenticate - User.php
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

class User {
	private $database = false;
	private $data = [];

	public function __set($name, $value) {
		$this->data[$name] = $value;
	}

	public function __get($name) {
		if (array_key_exists($name, $this->data)) {
			return $this->data[$name];
		}
	}

	public function __unset($name) {
		unset($this->data[$name]);
	}

	public function __isset($name) {
		return isset($this->data[$name]);
	}

	public function __construct($dsn) {
		@session_start();
		$this->database = new PDO('sqlite:' . $dsn);
		$this->authenticated = false;

		if (isset($_SESSION['username']) && isset($_SESSION['token'])) {
			$this->username = $_SESSION['username'];

			if ($this->hasValidToken($_SESSION['token']) && $this->hasValidTimeout()) {
				$this->authenticated = true;
				$this->updateAuthenticationTimeout();
				$this->populateUserInfo();
			}
		} elseif (isset($_POST['action'])) {
			$this->username = $_POST['username'];
			$this->authenticated = $this->userLogin($_POST['password']);
			$this->populateUserInfo();
		}
	}

	private function populateUserInfo() {
		$s = 'SELECT email, first, last, role FROM users WHERE username=:username';
		$q = $this->database->prepare($s);
		$q->bindValue(':username', $this->username);

		if (!$q->execute()) {
			return false;
		}

		$r = $q->fetchObject();

		$this->email = $r->email;
		$this->first = $r->first;
		$this->last = $r->last;
		$this->role = $r->role;
	}

	private function userLogin($password) {
		$s = 'SELECT hash, token FROM users WHERE username=:username';
		$q = $this->database->prepare($s);
		$q->bindValue(':username', $this->username);

		if (!$q->execute()) {
			return false;
		}

		$r = $q->fetchObject();
		$hash = hash('sha256', $this->username . $password . $r->token);

		if ($r->hash == $hash) {
			$this->updateAuthenticationTimeout();
			$this->updateAuthenticationToken($password);

			$ntoken = $this->generateAuthenticationToken();
			$nhash = hash('sha256', $this->username . $password . $ntoken);

			$s = 'UPDATE users SET hash=:hash, token=:token, timeout=:timeout WHERE username=:username';
			$q = $this->database->prepare($s);
			$q->bindValue(':hash', $nhash);
			$q->bindValue(':token', $ntoken);
			$q->bindValue(':timeout', time());
			$q->bindValue(':username', $this->username);

			if (!$q->execute()) {
				return false;
			}

			$_SESSION['username'] = $this->username;
			$_SESSION['token'] = $ntoken;
			return true;
		}

		return false;
	}

	public function userLogout() {
		$_SESSION = array();
		@session_destroy();
	}

	private function hasValidTimeout() {
		$s = 'SELECT timeout FROM users WHERE username=:username';
		$q = $this->database->prepare($s);
		$q->bindValue(':username', $this->username);

		if (!$q->execute()) {
			return false;
		}

		$r = $q->fetchObject();

		if ((time() - $r->timeout) > 600) {
			return false;
		}

		return true;
	}

	private function hasValidToken($token) {
		$s = 'SELECT token FROM users WHERE username=:username';
		$q = $this->database->prepare($s);
		$q->bindValue(':username', $this->username);

		if (!$q->execute()) {
			return false;
		}

		$r = $q->fetchObject();

		if ($r->token == $token) {
			return true;
		}

		return false;
	}

	private function updateAuthenticationTimeout() {
		$timeout = time();

		$s = 'UPDATE users SET timeout=:timeout WHERE username=:username';
		$q = $this->database->prepare($s);
		$q->bindValue(':timeout', $timeout);
		$q->bindValue(':username', $this->username);

		if (!$q->execute()) {
			return false;
		}

		return true;
	}

	private function updateAuthenticationToken($password) {
		$token = $this->generateAuthenticationToken(32);

		$s = 'UPDATE users SET token=:token WHERE username=:username';
		$q = $this->database->prepare($s);
		$q->bindValue(':token', $token);
		$q->bindValue(':username', $this->username);

		if (!$q->execute()) {
			return false;
		}

		$hash = hash('sha256', $this->username . $password . $token);
		$s = 'UPDATE users SET hash=:hash WHERE username=:username';
		$q = $this->database->prepare($s);
		$q->bindValue(':hash', $hash);
		$q->bindValue(':username', $this->username);

		if (!$q->execute()) {
			return false;
		}

		return true;
	}

	private function generateAuthenticationToken($length = 32) {
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
