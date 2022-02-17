<?php

namespace Firebase\JWT;

use OpenSSLAsymmetricKey;
use TypeError;
use InvalidArgumentException;

class Key
{
    /* string|resource|OpenSSLAsymmetricKey */ private $keyMaterial;
    /* string */ private $algorithm;

    /**
     * @param string|resource|OpenSSLAsymmetricKey $keyMaterial
     * @param string $algorithm
     */
    public function __construct(
        /* private string|resource|OpenSSLAsymmetricKey */
        $keyMaterial,
        /* private */
        string $algorithm
    ) {
        if (
            !is_string($keyMaterial)
            && !$keyMaterial instanceof OpenSSLAsymmetricKey
            && !is_resource($keyMaterial)
        ) {
            throw new TypeError('Key material must be a string, resource, or OpenSSLAsymmetricKey');
        }

        if (empty($keyMaterial)) {
            throw new InvalidArgumentException('Key material must not be empty');
        }

        if (empty($algorithm)) {
            throw new InvalidArgumentException('Algorithm must not be empty');
        }

        // TODO: Remove in PHP 8.0 in favor of class constructor property promotion
        $this->keyMaterial = $keyMaterial;
        $this->algorithm = $algorithm;
    }

    /**
     * Return the algorithm valid for this key
     *
     * @return string
     */
    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * @return string|resource|OpenSSLAsymmetricKey
     */
    public function getKeyMaterial()/*: string|resource|OpenSSLAsymmetricKey */
    {
        return $this->keyMaterial;
    }
}
