<?php

namespace Modulus\Security;

use Exception;
use AtlantisPHP\Swish\Route;
use Modulus\Security\Hash;
use Modulus\Security\RememberMe;

class Auth
{
  /**
   * $protectedRoutes
   *
   * @var array
   */
  public static $protectedRoutes = [
    'showLogin', 'login', 'showMagicLink', 'loginWithEmail', 'loginCallback',
    'logout', 'showRegistration', 'register', 'showForgotPassword', 'forgot',
    'showResetPassword', 'resetPassword', 'verify',
  ];

  /**
   * $user
   *
   * @var Model
   */
  protected static $user = null;

  /**
   * $provider
   *
   * @var string
   */
  public static $provider = 'web';

  /**
   * Register auth routes
   *
   * @return void
   */
  public static function routes()
  {
    // Login
    Route::get('/login', 'Auth\LoginController@showLoginPage')
          ->name('showLogin')
          ->middleware('guest');

    Route::post('/login', 'Auth\LoginController@login')
          ->name('login')
          ->middleware('guest');

    Route::get('/login/email', 'Auth\LoginController@showMagicLinkPage')
          ->name('showMagicLink')
          ->middleware('guest');

    Route::post('/login/email', 'Auth\LoginController@loginWithEmail')
          ->name('loginWithEmail')
          ->middleware('guest');

    Route::get('/login/callback/email/', 'Auth\LoginController@loginEmailCallback')
          ->name('loginCallback')
          ->middleware('guest');

    // Logout
    Route::post('/logout', 'Auth\LoginController@logout')
          ->name('logout')
          ->middleware('auth');

    // Register
    Route::get('/register', 'Auth\RegisterController@showRegistrationPage')
          ->name('showRegistration')
          ->middleware('guest');

    Route::post('/register', 'Auth\RegisterController@register')
          ->name('register')
          ->middleware('guest');

    // Password reset
    Route::get('/password/forgot', 'Auth\ForgotPasswordController@showForgotPasswordPage')
          ->name('showForgotPassword')
          ->middleware('guest');

    Route::post('/password/forgot', 'Auth\ForgotPasswordController@forgot')
          ->name('forgot')
          ->middleware('guest');

    Route::get('/password/reset', 'Auth\ForgotPasswordController@showResetPasswordPage')
          ->name('showResetPassword')
          ->middleware('guest');

    Route::post('/password/reset', 'Auth\ForgotPasswordController@resetPassword')
          ->name('resetPassword')
          ->middleware('guest');

    Route::get('/account/verify', 'Auth\RegisterController@verifyEmail')
          ->name('verify');


    $file = debug_backtrace()[0]['file'];

    foreach(Route::$routes as $key => $route) {
      if (in_array($route['name'], Auth::$protectedRoutes)) {
        $route['file'] = basename($file);

        Route::$routes[$key]['file'] = basename($file);
      }
    }
  }

  /**
   * Set provider
   *
   * @param string $provider
   * @return Auth
   */
  public static function provider(string $provider) : Auth
  {
    Auth::$provider = $provider;
    return new Auth;
  }

  /**
   * Check if user is a guest user or not
   *
   * @return bool
   */
  public static function isGuest() : bool
  {
    if (Auth::$user !== null) return false;
    return Remember::isGuest();
  }

  /**
   * Get authenticated user
   *
   * @return mixed
   */
  public static function user()
  {
    if (Auth::$user !== null) return Auth::$user;

    $model = '\\' . config('auth.provider.' . Auth::$provider . '.model');

    $model = (new $model)
                ->where(
                    config('auth.provider.' . Auth::$provider . '.with'),
                    Remember::user()
                  )
                ->first();

    if ($model == null) return Remember::logout();

    return $model;
  }

  /**
   * Grant user access
   *
   * @param Model $user
   * @return object
   */
  public static function grant($user) : object
  {
    Auth::$user = $user;
    return (object)array('status' => 'success');
  }

  /**
   * Log the user in
   *
   * @param Model $user
   * @return object
   */
  public static function login($user)
  {
    $token = $user->{config('auth.provider.' . Auth::$provider . '.with')} = Hash::random(70);
    $user->save();

    return Remember::login($token);
  }

  /**
   * log user out
   *
   * @return object
   */
  public static function logout()
  {
    return Remember::logout();
  }

  /**
   * Attemp login
   *
   * @param array $data
   * @param array $hidden
   * @return array
   */
  public static function attempt(array $data, ?array $hidden = null, ?string $provider = null) : ?array
  {
    if ($provider != null) Auth::provider($provider);

    $model = '\\' . config('auth.provider.' . Auth::$provider . '.model');

    $model = new $model;

    try {
      $protected = config('auth.provider.' . Auth::$provider . '.protects');
    }
    catch (Exception $e) {
      throw new Exception("The \"" . Auth::$provider . "\" provider doesn't protect any field.");
    }

    $protects = $data[$protected];

    unset($data[$protected]);

    $first = null;

    foreach ($data as $key => $value) {
      if (!in_array($key, $hidden)) {
        if ($first == null) $first = $key;
        $model = $model->where($key, $value);
      }
    }

    $model = $model->first();

    if ($model == null) return [$first => $protected . " or " . $first . " is incorrect."];

    $secretInformation = password_get_info($model->{$protected});

    if ($secretInformation['algoName'] == 'unknown' && $secretInformation['options'] == []) {
      if ($model->{$protected} !== $protects) return [$first => $protected . " or " . $first . " is incorrect."];
    }
    else {
      if (!password_verify($protects, $model->{$protected})) return [$first => $protected . " or " . $first . " is incorrect."];
    }

    return ['__MUST_RETURN__' => $model];
  }
}