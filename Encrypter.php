<?php

namespace Modulus\Security;

class Encrypter
{
  /**
   * $method
   *
   * @var string
   */
  protected $method = 'AES-128-CTR';

  /**
   * $key
   *
   * @var string
   */
  private $key;

  /**
   * __construct
   *
   * @param mixed $key
   * @param mixed $method
   * @return void
   */
  public function __construct($key = false, $method = false)
  {
    if(!$key) {
      $key = gethostname() . "|" . ip2long(isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : '');
    }

    if(ctype_print($key)) {
      $this->key = openssl_digest($key, 'SHA256', true);
    } else {
      $this->key = $key;
    }

    if($method) {
      if(in_array($method, openssl_get_cipher_methods())) {
        $this->method = $method;
      } else {
        die(__METHOD__ . ": unrecognised encryption method: {$method}");
      }
    }
  }

  /**
   * iv_bytes
   *
   * @return void
   */
  protected function iv_bytes()
  {
    return openssl_cipher_iv_length($this->method);
  }

  /**
   * encrypt
   *
   * @param mixed $data
   * @return void
   */
  public function encrypt(string $data)
  {
    $iv = openssl_random_pseudo_bytes($this->iv_bytes());
    $encrypted_string = bin2hex($iv) . openssl_encrypt($data, $this->method, $this->key, 0, $iv);
    return $encrypted_string;
  }

  /**
   * decrypt
   *
   * @param mixed $data
   * @return void
   */
  public function decrypt(string $data)
  {
    $iv_strlen = 2  * $this->iv_bytes();
    if(preg_match("/^(.{" . $iv_strlen . "})(.+)$/", $data, $regs)) {
      list(, $iv, $crypted_string) = $regs;
      $decrypted_string = openssl_decrypt($crypted_string, $this->method, $this->key, 0, hex2bin($iv));
      return $decrypted_string;
    } else {
      return false;
    }
  }

}
