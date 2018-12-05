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
 * @copyright   (c) 2019 Anthony Moral
 * @license 	MIT
 */
class Cryptozaure
{
	/** @var int Default maximum iteration char */
	const MAX = 70000;

	/** @var string Raw input content */
	private $raw = '';

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
		return hash('sha512', $this->prefix.$chr.$this->key);
	}

	/**
	 * Cryptozaure constructor.
	 *
	 * @param string $raw
	 * @param string $key
	 * @param string $prefix [optional]
	 * @return void
	 */
	public function __construct(string $raw, string $key, string $prefix = '')
	{
		$this->raw = $raw;
		$this->key = $key;
		$this->prefix = $prefix;
	}

	/**
	 * Return the encrypted content
	 *
	 * @return string
	 */
	public function encrypt(): string
	{
		$output = '';
		foreach (new MbStrIterator($this->raw) as $chr) {
			$output .= $this->hash($chr);
		}
		return $output;
	}

	/**
	 * Return the decrypted content
	 *
	 * @param int $max
	 * @return string
	 */
	public function decrypt(int $max = self::MAX): string
	{
		# Prepare stack
		$stack = [];
		for($i=0; $i <= $max; $i++) {
			$convmap = array(0x0, 0x10000, 0, 0xfffff);
			$chr = mb_decode_numericentity("&#$i;", $convmap, 'UTF-8');
			$stack[$this->hash($chr)] = $chr;
		}

		# Prepare plain text
		$output = '';
		$length = strlen($this->hash('x'));
		foreach (str_split($this->raw, $length) as $str) {
			$output .= $stack[$str] ?? '▮';
		}
		return $output;
	}
}