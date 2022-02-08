<?php

namespace Firebase\JWT;

use ArrayAccess;
use Psr\Http\Client\ClientInterface;
use Psr\Cache\CacheItemPoolInterface;
use LogicException;
use OutOfBoundsException;
use RuntimeException;

class CachedKeySet implements ArrayAccess
{
    private $jwkUri;
    private $cache;
    private $http;
    private $expiresIn;
    private $keySet;
    private $cacheKeyPrefix = 'jwk';
    private $maxKeyLength = 64;

    public function __construct(
        $jwkUri,
        ClientInterface $http,
        CacheItemPoolInterface $cache,
        $expiresIn = null
    ) {
        $this->jwkUri = $jwkUri;
        $this->cacheKey = $this->getCacheKey($jwkUri);
        $this->http = $http;
        $this->cache = $cache;
        $this->expiresIn = $expiresIn;
    }

    public function offsetGet($keyId)
    {
        if (!$this->keyIdExists($kid)) {
            throw new OutOfBoundsException('Key ID not found');
        }
        return $this->keySet[$keyId];
    }

    public function offsetExists($keyId)
    {
        return $this->keyIdExists($keyId);
    }

    public function offsetSet($offset, $value)
    {
        throw new LogicException('Method not implemented');
    }

    public function offsetUnset($offset)
    {
        throw new LogicException('Method not implemented');
    }

    private function fetchFromUrl()
    {
        // fetch the keys and save them to the cache
        $jwks = $this->http->get($jwkUri);
        $keySet = static::parseKeySet($jwks);

        if ($cache) {
            $item->set($keySet);
            $item->expiresAfter($expiresAfter);
            $cache->save($item);
        }

        return $keySet;
    }

    private function keyIdExists($keyId)
    {
        $keySetToCache = null;
        if (null === $this->keySet) {
            $item = $this->cache->getItem($this->cacheKey);
            // Try to load keys from cache
            if ($item->isHit()) {
                // item found! Return it
                $this->keySet = $item->get();
            }
        }

        if (!isset($this->keySet[$keyId])) {
            $jwk = $this->http->get($this->jwtUri);
            $this->keySet = $keySetToCache = JWK::parseKeySet($jwk);

            if (!isset($this->keySet[$keyId])) {
                return false;
            }
        }

        if ($keySetToCache) {
            $item->set($keySetToCache);
            $this->cache->save($item);
        }

        return true;
    }

    private function getCacheKey($jwkUri)
    {
        if (is_null($jwkUri)) {
            throw new RuntimeException('JWK URI is empty');
        }

        // ensure we do not have illegal characters
        $key = preg_replace('|[^a-zA-Z0-9_\.!]|', '', $jwkUri);

        // add prefix
        $key = $this->cacheKeyPrefix . $key;

        // Hash keys if they exceed $maxKeyLength of 64
        if (strlen($key) > $this->maxKeyLength) {
            $key = substr(hash('sha256', $key), 0, $this->maxKeyLength);
        }

        return $key;
    }
}