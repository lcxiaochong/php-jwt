<?php

namespace Firebase\JWT;

use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Prophecy\Argument;

class CachedKeySetTest extends TestCase
{
    private $testJwkUri = 'httpjwkuri';
    private $testJwkUriKey = 'jwkhttpjwkuri';
    private $testJwk1 = '{"keys": [{"kid":"foo","kty":"RSA","alg":"foo","n":"","e":""}]}';
    private $testJwk2 = '{"keys": [{"kid":"bar","kty":"RSA","alg":"bar","n":"","e":""}]}';

    private $googleRsaUri = 'https://www.googleapis.com/oauth2/v3/certs';
    // private $googleEcUri = 'https://www.gstatic.com/iap/verify/public_key-jwk';

    public function testOffsetSetThrowsException()
    {
        $this->setExpectedException(
            'LogicException',
            'Method not implemented'
        );

        $cachedKeySet = new CachedKeySet(
            $this->testJwkUri,
            $this->prophesize('Psr\Http\Client\ClientInterface')->reveal(),
            $this->prophesize('Psr\Http\Message\RequestFactoryInterface')->reveal(),
            $this->prophesize('Psr\Cache\CacheItemPoolInterface')->reveal()
        );

        $cachedKeySet['foo'] = 'bar';
    }

    public function testOffsetUnsetThrowsException()
    {
        $this->setExpectedException(
            'LogicException',
            'Method not implemented'
        );

        $cachedKeySet = new CachedKeySet(
            $this->testJwkUri,
            $this->prophesize('Psr\Http\Client\ClientInterface')->reveal(),
            $this->prophesize('Psr\Http\Message\RequestFactoryInterface')->reveal(),
            $this->prophesize('Psr\Cache\CacheItemPoolInterface')->reveal()
        );

        unset($cachedKeySet['foo']);
    }

    public function testOutOfBoundsThrowsException()
    {
        $this->setExpectedException(
            'OutOfBoundsException',
            'Key ID not found'
        );

        $cachedKeySet = new CachedKeySet(
            $this->testJwkUri,
            $this->getMockHttpClient($this->testJwk1),
            $this->getMockHttpFactory(),
            $this->getMockEmptyCache()
        );

        // keyID doesn't exist
        $cachedKeySet['bar'];
    }

    public function testWithExistingKeyId()
    {
        $cachedKeySet = new CachedKeySet(
            $this->testJwkUri,
            $this->getMockHttpClient($this->testJwk1),
            $this->getMockHttpFactory(),
            $this->getMockEmptyCache()
        );
        $this->assertInstanceOf('Firebase\JWT\Key', $cachedKeySet['foo']);
        $this->assertEquals('foo', $cachedKeySet['foo']->getAlgorithm());
    }

    public function testKeyIdIsCached()
    {
        $cacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
        $cacheItem->isHit()
            ->willReturn(true);
        $cacheItem->get()
            ->willReturn(JWK::parseKeySet(json_decode($this->testJwk1, true)));

        $cache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
        $cache->getItem($this->testJwkUriKey)
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->willReturn(true);

        $cachedKeySet = new CachedKeySet(
            $this->testJwkUri,
            $this->prophesize('Psr\Http\Client\ClientInterface')->reveal(),
            $this->prophesize('Psr\Http\Message\RequestFactoryInterface')->reveal(),
            $cache->reveal()
        );
        $this->assertInstanceOf('Firebase\JWT\Key', $cachedKeySet['foo']);
        $this->assertEquals('foo', $cachedKeySet['foo']->getAlgorithm());
    }

    public function testCachedKeyIdRefresh()
    {
        $cacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
        $cacheItem->isHit()
            ->shouldBeCalledOnce()
            ->willReturn(true);
        $cacheItem->get()
            ->shouldBeCalledOnce()
            ->willReturn(JWK::parseKeySet(json_decode($this->testJwk1, true)));
        $cacheItem->set(Argument::any())
            ->shouldBeCalledOnce()
            ->willReturn(true);

        $cache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
        $cache->getItem($this->testJwkUriKey)
            ->shouldBeCalledOnce()
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->shouldBeCalledOnce()
            ->willReturn(true);

        $cachedKeySet = new CachedKeySet(
            $this->testJwkUri,
            $this->getMockHttpClient($this->testJwk2), // updated JWK
            $this->getMockHttpFactory(),
            $cache->reveal()
        );
        $this->assertInstanceOf('Firebase\JWT\Key', $cachedKeySet['foo']);
        $this->assertEquals('foo', $cachedKeySet['foo']->getAlgorithm());

        $this->assertInstanceOf('Firebase\JWT\Key', $cachedKeySet['bar']);
        $this->assertEquals('bar', $cachedKeySet['bar']->getAlgorithm());
    }

    private function getMockHttpClient($testJwk)
    {
        $body = $this->prophesize('Psr\Http\Message\StreamInterface');
        $body->__toString()
            ->shouldBeCalledOnce()
            ->willReturn($testJwk);

        $response = $this->prophesize('Psr\Http\Message\ResponseInterface');
        $response->getBody()
            ->shouldBeCalledOnce()
            ->willReturn($body->reveal());

        $http = $this->prophesize('Psr\Http\Client\ClientInterface');
        $http->sendRequest(Argument::any())
            ->shouldBeCalledOnce()
            ->willReturn($response->reveal());

        return $http->reveal();
    }

    private function getMockHttpFactory()
    {
        $request = $this->prophesize('Psr\Http\Message\RequestInterface');
        $factory = $this->prophesize('Psr\Http\Message\RequestFactoryInterface');
        $factory->createRequest('get', $this->testJwkUri)
            ->shouldBeCalledOnce()
            ->willReturn($request->reveal());

        return $factory->reveal();
    }

    private function getMockEmptyCache()
    {
        $cacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
        $cacheItem->isHit()
            ->shouldBeCalledOnce()
            ->willReturn(false);
        $cacheItem->set(Argument::any())
            ->willReturn(true);

        $cache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
        $cache->getItem($this->testJwkUriKey)
            ->shouldBeCalledOnce()
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->willReturn(true);

        return $cache->reveal();
    }

    public function testCacheItemWithExpiresAfter()
    {
        $expiresAfter = 10;
        $cacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
        $cacheItem->isHit()
            ->shouldBeCalledOnce()
            ->willReturn(false);
        $cacheItem->set(Argument::any())
            ->shouldBeCalledOnce();
        $cacheItem->expiresAfter($expiresAfter)
            ->shouldBeCalledOnce();

        $cache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
        $cache->getItem($this->testJwkUriKey)
            ->shouldBeCalledOnce()
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->shouldBeCalledOnce();

        $cachedKeySet = new CachedKeySet(
            $this->testJwkUri,
            $this->getMockHttpClient($this->testJwk1),
            $this->getMockHttpFactory(),
            $cache->reveal(),
            $expiresAfter
        );
        $this->assertInstanceOf('Firebase\JWT\Key', $cachedKeySet['foo']);
        $this->assertEquals('foo', $cachedKeySet['foo']->getAlgorithm());
    }

    public function testFullIntegration()
    {
        if (!class_exists(TestMemoryCacheItemPool::class)) {
            $this->markTestSkipped('Use phpunit-system.xml.dist to run this tests');
        }

        $cache = new TestMemoryCacheItemPool();
        $http = new \GuzzleHttp\Client();
        $factory = new \GuzzleHttp\Psr7\HttpFactory();

        $cachedKeySet = new CachedKeySet(
            $this->googleRsaUri,
            $http,
            $factory,
            $cache
        );

        $this->assertArrayHasKey('182e450a35a2081faa1d9ae1d2d75a0f23d91df8', $cachedKeySet);
    }

    /*
     * For compatibility with PHPUnit 4.8 and PHP < 5.6
     */
    public function setExpectedException($exceptionName, $message = '', $code = null)
    {
        if (method_exists($this, 'expectException')) {
            $this->expectException($exceptionName);
            if ($message) {
                $this->expectExceptionMessage($message);
            }
        } else {
            parent::setExpectedException($exceptionName, $message, $code);
        }
    }
}
