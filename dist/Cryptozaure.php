<?php
namespace Coercive\Security\Cryptozaure;

use Coercive\Utility\Iterator\MbStrIterator;

/**
 * Cryptozaure : Encrypt and decrypt texts
 *
 * @package		Coercive\Security\Cryptozaure
 * @link		https://github.com/Coercive/Cryptozaure
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2020 Anthony Moral
 * @license 	MIT
 */
class Cryptozaure
{
	/** @var int Default maximum iteration char */
	const MAX = 70000;

	/** @var int Salt length */
	const SALT = 128;

	/** @var string Raw input content */
	private $raw = '';

	/** @var string Salt */
	private $salt = '';

	/** @var string Password key for en/decode */
	private $key = '';

	/** @var string Encode prefix */
	private $prefix = '';

	/**
	 * Special character hash with prefix and password
	 *
	 * @param string $chr
	 * @return string
	 */
	private function hash(string $chr): string
	{
		return hash('sha512', $this->prefix.$chr.$this->key.$this->salt);
	}

	/**
	 * OpenSsl random pseudo bytes
	 *
	 * @return string
	 */
	private function salt(): string
	{
		return bin2hex(openssl_random_pseudo_bytes(self::SALT));
	}

	/**
	 * XOR mix characters
	 *
	 * @param string $str
	 * @return string
	 */
	private function xor(string $str): string
	{
		for($i = 0; $i < strlen($str); $i++){
			$str[$i] = ~ $str[$i];
		}
		$str = base64_encode($str);
		return $str;
	}

	/**
	 * XOR un-mix characters
	 *
	 * @param string $str
	 * @return string
	 */
	private function rox(string $str): string
	{
		$str = (string) base64_decode($str);
		for($i = 0; $i < strlen($str); $i++){
			$str[$i] = ~ $str[$i];
		}
		return $str;
	}

	/**
	 * Cryptozaure constructor.
	 *
	 * @param string $raw
	 * @param string $key [optional]
	 * @param string $prefix [optional]
	 * @return void
	 */
	public function __construct(string $raw, string $key = '', string $prefix = '')
	{
		$this->raw = $raw;
		$this->key = $key;
		$this->prefix = $prefix;
		$this->salt = $this->salt();
	}

	/**
	 * Return the encrypted content
	 *
	 * @return string
	 */
	public function encrypt(): string
	{
		$output = '';
		$mix = $this->xor($this->raw);
		foreach (new MbStrIterator($mix) as $chr) {
			$output .= $this->hash($chr);
		}
		return $this->salt . $output;
	}

	/**
	 * Return the decrypted content
	 *
	 * @param int $max
	 * @return string
	 */
	public function decrypt(int $max = self::MAX): string
	{
		# Prepare salt
		$this->salt = substr($this->raw, 0, 2*self::SALT);
		$raw = substr($this->raw, 2*self::SALT);

		# Prepare stack
		$stack = [];
		for($i=0; $i <= $max; $i++) {
			$convmap = [0x0, 0x10000, 0, 0xfffff];
			$chr = mb_decode_numericentity("&#$i;", $convmap, 'UTF-8');
			$stack[$this->hash($chr)] = $chr;
		}

		# Prepare plain text
		$output = '';
		$length = strlen($this->hash('x'));
		foreach (str_split($raw, $length) as $str) {
			$output .= $stack[$str] ?? '▮';
		}
		$mix = $this->rox($output);
		return $mix;
	}
}
