<?php

namespace Modulus\Security;

class Hash
{
  /**
   * Make hash
   *
   * @param  mixed  $value
   * @return string
   */
  public static function make($value) : string
  {
    $default = config('hash.default');

    return password_hash(
      $value,
      config("hash.$default.algorithm"),
      config("hash.$default.options")
    );
  }

  /**
   * Creating a random string
   *
   * @param  int    $length
   * @param  string $keyspace
   * @return string
   */
  public static function random(int $length = 10, string $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') : string
  {
    $pieces = [];
    $max = mb_strlen($keyspace, '8bit') - 1;
    for ($i = 0; $i < $length; ++$i) {
      $pieces[] = $keyspace[random_int(0, $max)];
    }
    return implode('', $pieces);
  }

  /**
   * Creating a random string that contains special chars
   *
   * @param  int    $length
   * @param  string $keyspace
   * @return string
   */
  public static function secure(int $length = 40, string $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*()_-=+<>/\?;:{}[]|,.') : string
  {
    $pieces = [];
    $max = mb_strlen($keyspace, '8bit') - 1;
    for ($i = 0; $i < $length; ++$i) {
      $pieces[] = $keyspace[random_int(0, $max)];
    }

    return implode('', $pieces);
  }

  /**
   * Remove special char's from string
   *
   * @param string $string
   * @return string
   */
  public static function safe(string $string) : string
  {
    $split = str_split($string);

    foreach($split as $k => $char) {
      if (str_contains('~!@#$%^&*()_-=+<>/\?;:{}[]|,.', $char)) {
        unset($split[$k]);
      }
    }

    return implode('', $split);
  }


}