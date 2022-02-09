<?php

namespace Firebase\JWT;

use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use GuzzleHttp\Client;
use RuntimeException;

if (file_exists($file = __DIR__ . '/../vendor/autoload.php')) {
    require_once $file;
} else {
    die('Unable to find autoload.php file, please use composer to load dependencies:

wget http://getcomposer.org/composer.phar
php composer.phar install

Visit http://getcomposer.org/ for more information.

');
}

// For http objects
if (!class_exists(Client::class)) {
    throw new RuntimeException('You must run "composer require guzzlehttp/guzzle" to execute the integration tests');
}

// For cache objects
if (!class_exists(CacheItemPoolInterface::class)) {
    // throw new RuntimeException('You must run "composer require psr/cache" to execute the integration tests');
}

/**
 * A cache item pool
 */
final class TestMemoryCacheItemPool implements CacheItemPoolInterface
{
    private $items;
    private $deferredItems;

    public function getItem($key)
    {
        return current($this->getItems([$key]));
    }

    public function getItems(array $keys = [])
    {
        $items = [];

        foreach ($keys as $key) {
            $items[$key] = $this->hasItem($key) ? clone $this->items[$key] : new TestMemoryCacheItem($key);
        }

        return $items;
    }

    public function hasItem($key)
    {
        return isset($this->items[$key]) && $this->items[$key]->isHit();
    }

    public function clear()
    {
        $this->items = [];
        $this->deferredItems = [];

        return true;
    }

    public function deleteItem($key)
    {
        return $this->deleteItems([$key]);
    }

    public function deleteItems(array $keys)
    {
        foreach ($keys as $key) {
            unset($this->items[$key]);
        }

        return true;
    }

    public function save(CacheItemInterface $item)
    {
        $this->items[$item->getKey()] = $item;

        return true;
    }

    public function saveDeferred(CacheItemInterface $item)
    {
        $this->deferredItems[$item->getKey()] = $item;

        return true;
    }

    public function commit()
    {
        foreach ($this->deferredItems as $item) {
            $this->save($item);
        }

        $this->deferredItems = [];

        return true;
    }
}

/**
 * A cache item.
 */
final class TestMemoryCacheItem implements CacheItemInterface
{
    private $key;
    private $value;
    private $expiration;
    private $isHit = false;

    public function __construct($key)
    {
        $this->key = $key;
    }

    public function getKey()
    {
        return $this->key;
    }

    public function get()
    {
        return $this->isHit() ? $this->value : null;
    }

    public function isHit()
    {
        if (!$this->isHit) {
            return false;
        }

        if ($this->expiration === null) {
            return true;
        }

        return $this->currentTime()->getTimestamp() < $this->expiration->getTimestamp();
    }

    public function set($value)
    {
        $this->isHit = true;
        $this->value = $value;

        return $this;
    }

    public function expiresAt($expiration)
    {
        $this->expiration = $expiration;
        return $this;
    }

    public function expiresAfter($time)
    {
        $this->expiration = $this->currentTime()->add(new \DateInterval("PT{$time}S"));
        return $this;
    }

    protected function currentTime()
    {
        return new \DateTime('now', new \DateTimeZone('UTC'));
    }
}
