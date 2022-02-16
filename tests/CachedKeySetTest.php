<?php

namespace Firebase\JWT;

use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Prophecy\Argument;
use LogicException;
use OutOfBoundsException;

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
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Method not implemented');

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
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Method not implemented');

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
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('Key ID not found');

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

    public function testJwtVerify()
    {
        $privKey1 = file_get_contents(__DIR__ . '/data/rsa1-private.pem');
        $payload = array('sub' => 'foo', 'exp' => strtotime('+10 seconds'));
        $msg = JWT::encode($payload, $privKey1, 'RS256', 'jwk1');

        $cacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
        $cacheItem->isHit()
            ->willReturn(true);
        $cacheItem->get()
            ->willReturn(JWK::parseKeySet(
                json_decode(file_get_contents(__DIR__ . '/data/rsa-jwkset.json'), true)
            ));

        $cache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
        $cache->getItem($this->testJwkUriKey)
            ->willReturn($cacheItem->reveal());

        $cachedKeySet = new CachedKeySet(
            $this->testJwkUri,
            $this->prophesize('Psr\Http\Client\ClientInterface')->reveal(),
            $this->prophesize('Psr\Http\Message\RequestFactoryInterface')->reveal(),
            $cache->reveal()
        );

        $result = JWT::decode($msg, $cachedKeySet);

        $this->assertEquals("foo", $result->sub);
    }

    /**
     * @dataProvider provideFullIntegration
     */
    public function testFullIntegration($jwkUri, $kid)
    {
        if (!class_exists(TestMemoryCacheItemPool::class)) {
            $this->markTestSkipped('Use phpunit-system.xml.dist to run this tests');
        }

        $cache = new TestMemoryCacheItemPool();
        $http = new \GuzzleHttp\Client();
        $factory = new \GuzzleHttp\Psr7\HttpFactory();

        $cachedKeySet = new CachedKeySet(
            $jwkUri,
            $http,
            $factory,
            $cache
        );

        $this->assertArrayHasKey($kid, $cachedKeySet);
    }

    public function provideFullIntegration()
    {
        return [
            [$this->googleRsaUri, '182e450a35a2081faa1d9ae1d2d75a0f23d91df8'],
            // [$this->googleEcUri, 'LYyP2g']
        ];
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
}
