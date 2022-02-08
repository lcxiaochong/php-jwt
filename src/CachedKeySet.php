<?php

namespace Firebase\JWT;

use ArrayAccess;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Cache\CacheItemPoolInterface;
use LogicException;
use OutOfBoundsException;
use RuntimeException;

class CachedKeySet implements ArrayAccess
{
    private $jwkUri;
    private $httpClient;
    private $httpFactory;
    private $cache;
    private $expiresAfter;

    private $cacheItem;
    private $keySet;
    private $cacheKeyPrefix = 'jwk';
    private $maxKeyLength = 64;

    public function __construct(
        $jwkUri,
        ClientInterface $httpClient,
        RequestFactoryInterface $httpFactory,
        CacheItemPoolInterface $cache,
        $expiresAfter = null
    ) {
        $this->jwkUri = $jwkUri;
        $this->cacheKey = $this->getCacheKey($jwkUri);
        $this->httpClient = $httpClient;
        $this->httpFactory = $httpFactory;
        $this->cache = $cache;
        $this->expiresAfter = $expiresAfter;
    }

    public function offsetGet($keyId)
    {
        if (!$this->keyIdExists($keyId)) {
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

    private function keyIdExists($keyId)
    {
        $keySetToCache = null;
        if (null === $this->keySet) {
            $item = $this->getCacheItem();
            // Try to load keys from cache
            if ($item->isHit()) {
                // item found! Return it
                $this->keySet = $item->get();
            }
        }

        if (!isset($this->keySet[$keyId])) {
            $request = $this->httpFactory->createRequest('get', $this->jwkUri);
            $jwkResponse = $this->httpClient->sendRequest($request);
            $jwk = json_decode((string) $jwkResponse->getBody(), true);
            $this->keySet = $keySetToCache = JWK::parseKeySet($jwk);

            if (!isset($this->keySet[$keyId])) {
                return false;
            }
        }

        if ($keySetToCache) {
            $item = $this->getCacheItem();
            $item->set($keySetToCache);
            if ($this->expiresAfter) {
                $item->expiresAfter($this->expiresAfter);
            }
            $this->cache->save($item);
        }

        return true;
    }

    private function getCacheItem()
    {
        if ($this->cacheItem) {
            return $this->cacheItem;
        }

        return $this->cacheItem = $this->cache->getItem($this->cacheKey);
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
