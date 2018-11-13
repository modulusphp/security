<?php

namespace Modulus\Security;

use Exception;
use Birke\Rememberme\Authenticator;
use Birke\Rememberme\Cookie\PHPCookie;
use Birke\Rememberme\Token\DefaultToken;
use Birke\Rememberme\Storage\FileStorage;

class Remember
{
  /**
   * $tokensDir
   *
   * @var string
   */
  public static $tokensDir;

  /**
   * $expire
   *
   * @var string
   */
  public static $expire;

  /**
   * $storage
   *
   * @var FileStorage
   */
  public static $storage;

  /**
   * $rememberMe
   *
   * @var Authenticator
   */
  public static $rememberMe;

  /**
   * Boot remember me component
   *
   * @return void
   */
  public function boot()
  {
    if (!is_dir(Remember::$tokensDir)) {
      mkdir(Remember::$tokensDir, 0777, true);
    }

    $this->hasTokens();
    $this->configure();
    $this->start();
  }

  /**
   * Check if the tokens directory exists or is writable
   *
   * @return void
   */
  public function hasTokens()
  {
    if (!is_writable(Remember::$tokensDir) || !is_dir(Remember::$tokensDir)) {
      $tokens = Remember::$tokensDir;
      return $this->exception("'$tokens' does not exist or is not writable by the web server");
    }
  }

  /**
   * Configure remember me
   *
   * @return void
   */
  public function configure()
  {
    $tokenGenerator = new DefaultToken(94, DefaultToken::FORMAT_BASE64);

    $expire = strtotime(Remember::$expire, 0);
    $cookie = new PHPCookie("application_session", $expire, "/", "", true, true);

    Remember::$storage = new FileStorage(Remember::$tokensDir);
    Remember::$rememberMe = new Authenticator(Remember::$storage, $tokenGenerator, $cookie);
  }

  /**
   * Start remember me
   *
   * @return void
   */
  public function start()
  {
    $rememberMe = Remember::$rememberMe;
    $loginResult = $rememberMe->login();

    if ($loginResult->isSuccess()) {
      $_SESSION['_uas'] = $loginResult->getCredential();
      $_SESSION['remembered_by_cookie'] = true;
      return;
    }

    if ($loginResult->hasPossibleManipulation()) {
      exit();
    }

    if ($loginResult->isExpired() && !empty($_SESSION['_uas']) && !empty($_SESSION['remembered_by_cookie'])) {
      $rememberMe->clearCookie();
      unset($_SESSION['_uas']);
      unset($_SESSION['remembered_by_cookie']);
      exit();
    }
    if ($loginResult->isExpired() && !empty($_SESSION['_uas'])) {
      sleep(5);
    }
  }

  /**
   * Check if is guest
   *
   * @return bool
   */
  public static function isGuest() : bool
  {
    if (isset($_SESSION['_uas'])) {
      if ($_SESSION['_uas'] == null) {
        return true;
      }
      else {
        return false;
      }
    }
    return true;
  }

  /**
   * Get authenticated user
   *
   * @return void
   */
  public static function user()
  {
    if (isset($_SESSION['_uas'])) {
      return $_SESSION['_uas'];
    }
  }

  /**
   * Authenticate user
   *
   * @param mixed $token
   * @return void
   */
  public static function login($token)
  {
    $rememberMe = Remember::$rememberMe;
    $rememberMe->setCleanExpiredTokensOnLogin(true);

    $_SESSION['_uas'] = $token;

    $rememberMe->createCookie($token);

    return (object)array('status' => 'success');
  }

  /**
   * Unauthenticate user
   *
   * @return void
   */
  public static function logout()
  {
    $storage = Remember::$storage;
    $rememberMe = Remember::$rememberMe;

    $storage->cleanAllTriplets(isset($_SESSION['_uas']) ? $_SESSION['_uas'] : '');

    $_SESSION = [];

    session_regenerate_id();
    $rememberMe->clearCookie();

    return (object)array('status' => 'success');
  }

  /**
	 * Throw new Exception
	 *
	 * @param  string $message
   * @return void
	 */
  private function exception(string $message) : void
  {
    throw new Exception($message);
  }
}
