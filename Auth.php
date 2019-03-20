<?php

namespace Modulus\Security;

use Exception;
use AtlantisPHP\Swish\Route;
use Modulus\Support\Extendable;

class Auth
{
  use Extendable;

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
    Route::group(['namespace' => 'Auth'], function () {

      Route::group(['middleware' => ['guest']], function () {

        Route::get('login', 'LoginController@showLoginPage')->name('showLogin');
        Route::post('login', 'LoginController@login')->name('login');

        Route::get('login/email', 'LoginController@showMagicLinkPage')->name('showMagicLink');
        Route::post('login/email', 'LoginController@loginWithEmail')->name('loginWithEmail');
        Route::get('login/callback/email/', 'LoginController@loginEmailCallback')->name('loginCallback');

        Route::get('register', 'RegisterController@showRegistrationPage')->name('showRegistration');
        Route::post('register', 'RegisterController@register')->name('register');

        Route::get('password/forgot', 'ForgotPasswordController@showForgotPasswordPage')->name('showForgotPassword');
        Route::post('password/forgot', 'ForgotPasswordController@forgot')->name('forgot');

        Route::get('password/reset', 'ForgotPasswordController@showResetPasswordPage')->name('showResetPassword');
        Route::post('password/reset', 'ForgotPasswordController@resetPassword')->name('resetPassword');

      });

      Route::get('logout', 'LoginController@logout')->name('logout')->middleware('private', 'auth');
      Route::get('account/verify', 'RegisterController@verifyEmail')->name('verify');

    });
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
                    Remember::user() ?? 'null'
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
   * @return Model|array
   */
  public static function attempt(array $data, ?array $hidden = null, ?string $provider = null)
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

    return $model;
  }
}
