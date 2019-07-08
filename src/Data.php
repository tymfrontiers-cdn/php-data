<?php
namespace TymFrontiers;

class Data{
  const RAND_LOWERCASE = 'lowercase';
  const RAND_UPPERCASE = 'uppercase';
  const RAND_NUMBERS = 'numbers';
  const RAND_MIXED = 'mixed';
  const RAND_MIXED_UPPER = 'mixedupper';
  const RAND_MIXED_LOWER = 'mixedlower';
  # encryption key, to be set later
  private static $_enc_key;
  private static $_sign_salt = "cHuRa#abrasp7!aSteMUK";
  protected $_rand_range = 'AaBbCcDdEeFfGgHhJjKkMmNnPpQqRrSsTtUuVvWwXxYyZz23456789';

  # Errors incase of any
  public $errors = [];
  # How error is pushed to this array
  # key => [ // key can be method name/instannce where error occured
  #   [
  #     int view_rank, // who can see this error. Check https://github.com/tymfrontiers-cdn/user-ranking-doc
  #     int error_type, // php error type
  #     string error_message, // Error itself
  #     string file, // where error ocured. e.g __FILE__
  #     string line // where error ocured. e.g __LINE__
  #   ]
  # ]

  function __construct(){
    self::_init();
  }

  public static function encrypt(string $data, string $enc_key='') {
    // Remove the base64 encoding from our key
    $encryption_key = empty($enc_key) ? \base64_decode(self::$_enc_key) : \base64_decode($enc_key);
    // Generate an initialization vector
    $iv = \openssl_random_pseudo_bytes( \openssl_cipher_iv_length('aes-256-cbc'));
    // Encrypt the data using AES 256 encryption in CBC mode using our encryption key and initialization vector.
    $encrypted = \openssl_encrypt($data, 'aes-256-cbc', $encryption_key, 0, $iv);
    // The $iv is just as important as the key for decrypting, so save it with our encrypted data using a unique separator (::)
    return $encrypted . '::' . $iv;
  }
  public static function decrypt(string $data, string $enc_key='') {
    // Remove the base64 encoding from our key
    $encryption_key = empty($enc_key) ? \base64_decode(self::$_enc_key) : \base64_decode($enc_key);
    // To decrypt, split the encrypted data from our IV - our unique separator used was "::"
    list($encrypted_data, $iv) = \explode('::', $data, 2);
    return \openssl_decrypt($encrypted_data, 'aes-256-cbc', $encryption_key, 0, $iv);
    // return $string;
  }
  public static function encodeEncrypt(string $data, string $enc_key='') {
    return \base64_encode( self::encrypt($data, $enc_key) );
  }
  public static function decodeDecrypt($data, string $enc_key='') {
    return self::decrypt( \base64_decode($data), $enc_key );
  }
  public static function signString($string) {
    // Using $salt makes it hard to guess how $checksum is generated
    // Caution: changing salt will invalidate all signed strings
    $checksum = \sha1($string.self::$_sign_salt); // Any hash algorithm would work
    // return the string with the checksum at the end
    return $string.'--'.$checksum;
  }
  public static function isSignString($signed_string) {
    $array = \explode('--', $signed_string);
    if( \count($array) != 2) {
      // string is malformed or not signed
      return false;
    }


    // Sign the string portion again. Should create same
    // checksum and therefore the same signed string.
    $new_signed_string = self::signString($array[0]);
    if($new_signed_string == $signed_string) {
      return $array[0];
    } else {
      return false;
    }
  }
  // one-way hashing for password
  public static function pwdHash(string $password) {
    return \crypt($password,"$2y$10$".self::genSalt(22));
  }
  public static function pwdCheck(string $search,string $password){
    $hash = \crypt($search,$password);
    return $hash === $password ? true : false;
  }
  public static function outprint($data, string $method = 'json', string $wrapper='', bool $echo=true){
    $out = !empty($wrapper) ? "{$wrapper}(" : "";
    if( $method == 'json' ){
      $out .= \json_encode($data);
    }
    $out .= !empty($wrapper) ? ")" : "";
    if( $echo ){
      echo $out;
    }else{
      return $out;
    }
  }
  public static function genSalt($len){
    $len = (int)$len;
    $unique_rand = \md5( \uniqid( \mt_rand(),true) );
    $base64_str = \base64_encode($unique_rand);
    $base64_str = \str_replace('+', '.', $base64_str);
    return \substr($base64_str, 0,$len);
  }
  public static function genCode(int $len=5){
    return self::uniqueRand('',$len,DATA_RAND_NUMBERS);
    // $random_number=''; // set up a blank string
    // $count=0;
    // while ( $count < $len ) {
    //   $random_digit = mt_rand(0, 9);
    //   $random_number .= $random_digit;
    //   $count++;
    // }
    // return $random_number;
  }
  public static function genAlnumeric(string $chars='',int $len=6){
    return self::uniqueRand($chars,$len,DATA_RAND_MIXED );
    // $chars = ( !empty($chars) && strlen($chars) > $len ) ? $chars : $this->_rand_range;
    // $string = '';
    // $max = strlen($chars) - 1;
    // for ($i = 0; $i < $len; $i++) {
    //   $string .= $chars[mt_rand(0, $max)];
    // }
    // return $string;
  }
  public static function getLen($text='',$len=0){
    $len = (int)$len > 5 ? (int)$len : 150;
    if( \strlen($text) > $len) {
      $text = \substr($text, 0, \strpos($text, ' ', $len));
    }
    return $text.' ..';
  }
  public static function restoreKey( string $key){
    if( $key ) self::_createKey($key);
  }
  public function toByte(int $val=1, string $from='mb'){
    switch (\strtolower($from)) {
      case 'kb':
          return $val * 1024;
        break;
      case 'mb':
          return $val * 1024 * 1024;
        break;
      case 'gb':
          return $val * 1024 * 1024 * 1024;
        break;
      case 'tb':
          return $val * 1024 * 1024 * 1024 * 1024;
        break;

      default:
        return 0;
        break;
    }
  }
  public function fromByte($to='mb'){ return null;}
  public static function keyBackup(){
    return self::$_enc_key;
  }

  // these methods requires libphone number
  public function phoneToLocal( string $phone){
    $phoneUtil = \libphonenumber\PhoneNumberUtil::getInstance();
    try {
       if( $parsed = $phoneUtil->parse($phone,null) ){
         if( $phoneUtil->isValidNumber($parsed) ){
           return $phoneUtil->format($parsed, \libphonenumber\PhoneNumberFormat::NATIONAL);
         }
       }
     } catch (\libphonenumber\NumberParseException $e) {
       $this->errors['phoneToLocal'][] = [
         2, // viewer rank
         256, // error type
         $e->getMessage(), // error message
         __FILE__, // file for errors
         __LINE__ // line for errors
       ];
       return false;
     }
  }
  public function phoneToIntl($phone,$country_code='NG'){
    $country_code = \strtoupper($country_code);
    $phoneUtil = \libphonenumber\PhoneNumberUtil::getInstance();
    try {
         if( $parsed = $phoneUtil->parse($phone, $country_code) ){
           if( $phoneUtil->isValidNumber($parsed) ){
             return $phoneUtil->format($parsed, \libphonenumber\PhoneNumberFormat::E164);
           }
         }
       } catch (\libphonenumber\NumberParseException $e) {
         $this->errors['phoneToIntl'][] = [
           2, // viewer rank
           256, // error type
           $e->getMessage(), // error message
           __FILE__, // file for errors
           __LINE__ // line for errors
         ];
         return false;
       }
  }
  #requires tymfrontiers/php-mysql-database
  #requires tymfrontiers/php-mysql-database-object
  public static function uniqueRand(string $salt='', int $len=6, string $case='mixed', bool $asn = true, string $dbase='', string $tbl='', string $col=''){
    $ini_salt = $salt;
    # arguements
    # salt: [string] characters used for generating result
    # len: [int] return character length
    # case: [string] return character case >> lowercase, uppercase, numbers, mixed
    # asn: [bool] includ alphabet similar to number e.g, 0=o, 1=i
    # dbase: [string] database name for proper check
    # tbl: [string] table name for proper check
    # col: [string] column name for proper check
    $salts = [
      "lower1" => "abcdefghijklmnopqrstuvwxyz",
      "lower2" =>  "zyxwvutsrqponmlkjihgfedcba",
      "upper1" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      "upper2" =>  "ZYXWVUTSRQPONMLKJIHGFEDCBA",
      "numbers" => !empty($salt) ? $salt : "0123456789876543210"
    ];
    $salts['lowercase'] = $salts['lower1'] . $salts['lower2'];
    $salts['uppercase'] = $salts['upper1'] . $salts['upper2'];
    $salts['mixed'] = !empty($salt) ? $salt :
      $salts['lower1'] . $salts['numbers'] . $salts['upper2'] .
      $salts['numbers'] . $salts['lower2'] .$salts['numbers'] .
      $salts['upper1'];
    $salts['mixedupper'] = $salts['upper1'] . $salts['numbers'] . $salts['upper2'] . $salts['numbers'];
    $salts['mixedlower'] = $salts['lower1'] . $salts['numbers'] . $salts['lower2'] . $salts['numbers'];
    $salt = $salts[$case];
    if( !$asn ) $salt = \str_replace(['0','o','O','i','1','I','l'],'',$salt);
    $code  = self::_gen($salt,$len);

  	if( !empty($dbase) && !empty($tbl) && !empty($col)){
  		return empty(
        ( new MultiForm($dbase,$tbl) )->findBySql("SELECT * FROM :db:.:tbl: WHERE `{$col}`='{$code}' LIMIT 1 ")
        ) ? $code : self::uniqueRand($ini_salt,$len,$case,$asn,$dbase,$tbl,$col);
  	}
  	return $code;
  }
  // reserved methods
  private static function _gen(string $salt, int $len){
    $string = '';
    $max = \strlen($salt) - 1;
    for ($i = 0; $i < $len; $i++) {
      $string .= $salt[ \mt_rand(0, $max)];
    }
    return $string;
  }
  private static function _init(){
    // check for definition of project directory
    if (!\defined('PRJ_ROOT')) {
      throw new \Exception("[PRJ_ROOT]: defined! Kindly define a constant 'PRJ_ROOT' for path to root of your project.", 256);
    } if (!\file_exists(PRJ_ROOT) || !\is_readable(PRJ_ROOT) || !\is_writable(PRJ_ROOT)) {
      throw new \Exception("Project path: " . PRJ_ROOT . " does not exist or is not readable.", 1);
    }
    $dir = PRJ_ROOT . "/storage/.runtym/.tym/php-data";
    if (!\file_exists($dir)) {
      // create directory
      \mkdir($dir,0777,true);
    }

    $key_file = $dir.'/.data_key.php';
    if( !\file_exists($key_file) || !\is_readable($key_file) ){
      self::_createKey();
    }
    $key = \file_get_contents($key_file);
    $key = \trim( \str_replace("<?php",'',$key) );
    self::$_enc_key = $key;
  }
  private static function _createKey(string $key=''){
    // check for definition of project directory
    if (!\defined('PRJ_ROOT')) {
      throw new \Exception("[PRJ_ROOT]: defined! Kindly define a constant 'PRJ_ROOT' for path to root of your project.", 1);
    } if (!\file_exists(PRJ_ROOT) || !\is_readable(PRJ_ROOT) || !\is_writable(PRJ_ROOT)) {
      throw new \Exception("Project path: " . PRJ_ROOT . " does not exist or is not readable.", 1);
    }
    $dir = PRJ_ROOT . "/storage/.runtym/.tym/php-data";
    if (!\file_exists($dir)) {
      // create directory
      \mkdir($dir,0777,true);
    }

    $key_file = $dir.'/.data_key.php';
    $key =  empty($key) ? "<?php ".\base64_encode( \openssl_random_pseudo_bytes(32)) :
                          "<?php ".$key;
    if( !\file_put_contents($key_file,$key) ){
      throw new \Exception("Error writing key file due to incorrect permision", 1);
    }
  }

}
