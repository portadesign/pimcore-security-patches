<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('GHSA-jmh9-6rjq-gjh9')]
final class ImageEditorContentSecurityPolicyTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;

    private const USERNAME = 'pd-sec-csp-admin';

    private const ASSET_KEY = 'pd-sec-csp-image.png';

    private const PNG = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';

    private \Pimcore\Model\Asset\Image $asset;

    protected function setUp(): void
    {
        $this->removeFixtures();

        $user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::USERNAME,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
            'admin' => true,
        ]);
        $this->signIn($user);

        $asset = new \Pimcore\Model\Asset\Image();
        $asset->setParentId(1);
        $asset->setFilename(self::ASSET_KEY);
        $asset->setData((string) base64_decode(self::PNG, true));
        $asset->save();
        $this->asset = $asset;
    }

    protected function tearDown(): void
    {
        $this->authenticate(null);
        $this->removeFixtures();
    }

    public function testEditorResponseCarriesExactContentSecurityPolicy(): void
    {
        $response = $this->editor();

        $this->assertSame(
            str_replace('{nonce}', $this->nonceOf($response), $this->expectedPolicy()),
            $response->headers->get('Content-Security-Policy'),
        );
    }

    public function testInlineConfigScriptUsesTheNonceOfTheHeader(): void
    {
        $response = $this->editor();

        $this->assertSame(1, preg_match_all('/<script nonce="[^"]+">/', (string) $response->getContent()));
        $this->assertStringContainsString('<script nonce="' . $this->nonceOf($response) . '">', (string) $response->getContent());
    }

    public function testNonceChangesBetweenResponses(): void
    {
        $this->assertNotSame($this->nonceOf($this->editor()), $this->nonceOf($this->editor()));
    }

    public function testEditorMarkupContainsNoInlineEventHandler(): void
    {
        $this->assertSame(0, preg_match('/\son[a-z]+\s*=/i', (string) $this->editor()->getContent()));
    }

    public function testControlEditorMarkupStillLoadsTheBundleAndTheAsset(): void
    {
        $content = (string) $this->editor()->getContent();

        $this->assertStringContainsString('<script src="/bundles/pimcoreadmin/js/lib/minipaint/dist/bundle.js"></script>', $content);
        $this->assertStringContainsString('<img style="visibility: hidden" id=\'image\' src="/admin/asset/get-asset?id=' . $this->asset->getId() . '" />', $content);
    }

    public function testAdminCspListenerKeepsThePolicyOfTheEditor(): void
    {
        $container = \Pimcore::getContainer();
        $property = new \ReflectionProperty(\Pimcore\Config::class, 'systemConfig');
        $original = $property->getValue();
        $enabled = \Pimcore\Config::getSystemConfiguration();
        $enabled['admin_csp_header'] = ['enabled' => true, 'exclude_paths' => []];
        $property->setValue(null, $enabled);

        try {
            $request = \Symfony\Component\HttpFoundation\Request::create('/admin/asset/image-editor?id=' . $this->asset->getId());
            $resolver = $container->get(\Pimcore\Http\Request\Resolver\PimcoreContextResolver::class);
            $resolver->setPimcoreContext($request, \Pimcore\Http\Request\Resolver\PimcoreContextResolver::CONTEXT_ADMIN);
            $response = $this->editor();
            $policy = $response->headers->get('Content-Security-Policy');

            $listener = new \Pimcore\Bundle\AdminBundle\EventListener\AdminSecurityListener(
                $container->get(\Pimcore\Http\RequestHelper::class),
                $container->get(\Pimcore\Bundle\AdminBundle\Security\ContentSecurityPolicyHandler::class),
                new \Pimcore\Config(),
            );
            $listener->setPimcoreContextResolver($resolver);
            $listener->onKernelResponse(new \Symfony\Component\HttpKernel\Event\ResponseEvent(
                $container->get('kernel'),
                $request,
                \Symfony\Component\HttpKernel\HttpKernelInterface::MAIN_REQUEST,
                $response,
            ));
        } finally {
            $property->setValue(null, $original);
        }

        $this->assertSame($policy, $response->headers->get('Content-Security-Policy'));
    }

    private function signIn(\Pimcore\Model\User $user): void
    {
        $proxy = new \Pimcore\Security\User\User($user);
        $this->tokenStorage()->setToken(new \Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken($proxy, 'pimcore_admin', $proxy->getRoles()));
    }

    private function editor(): \Symfony\Component\HttpFoundation\Response
    {
        $controller = \Pimcore::getContainer()->get(\Pimcore\Bundle\AdminBundle\Controller\Admin\Asset\AssetController::class);

        return $controller->imageEditorAction(new \Symfony\Component\HttpFoundation\Request(['id' => $this->asset->getId()]));
    }

    private function nonceOf(\Symfony\Component\HttpFoundation\Response $response): string
    {
        preg_match("/'nonce-([^']+)'/", (string) $response->headers->get('Content-Security-Policy'), $matches);

        return $matches[1] ?? '';
    }

    private function expectedPolicy(): string
    {
        return implode('; ', [
            "default-src 'self'",
            "script-src 'self' 'nonce-{nonce}'",
            "script-src-attr 'unsafe-hashes' " . implode(' ', [
                "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='",
                "'sha256-j79AgvnEUsAcw0qnwUrh8aySYx8K18z2/DIPIpAHt7g='",
                "'sha256-0IADUaARfPj5PESgXKatfDu6/zc0Pa9u7MzxdEdPXYc='",
                "'sha256-UoVSD/3yjBKMQxYXaWVnOWNcje+f8w8tH27OHutfphQ='",
                "'sha256-A/YOgYehlOs1aVj+EgroPQRKDwkpnxFVvNHTm8aBE3w='",
                "'sha256-WFHvpZcb5GghW9SFwW605t35UVc483R1rGwCSo1SdCY='",
                "'sha256-4lBCDBRBMu/+LEhnLLbHrsy/A52jdhGQLctcwYVJmws='",
                "'sha256-B63HWD442QRjcWnzIlS4q+YGq+i3aJl5Pu9EDd/t5rI='",
                "'sha256-iwcenCGuyy5nwBi7eMssuYbJdcN2W+6UWUF3yG8zE6Y='",
                "'sha256-xF7RCj6vLCrcLMG882SRdSGdJL9RXUB+0pEDZmKrefs='",
                "'sha256-q8zlyZaHwacBp0SyhJ+O9c9RvgaEkp93mqH9j92hFuc='",
                "'sha256-msQ6Bh9cYCr2Uua2soXxHuTXuzQY3boDz37JBiwd0F4='",
                "'sha256-dCmAx5r54Gs7TQQ3LzJVPLrKc+3uNnRl4ADTRssofoU='",
                "'sha256-x1Eg3s6d7QMA7QdHzhwTA9F5HAZrOG8N3lPsxWKWRHc='",
                "'sha256-T9wy6548GYIyelmkmtlWC+dmOcIedXmaT/XIN1fMesg='",
                "'sha256-J4KQkUPTbA5POEp78+G64p/4XiviejONLRiPP52H/Ew='",
                "'sha256-FHOJuWg7V7aYUkWBeSdT+5Ap9ou22Ssi5QDS3VJsdl0='",
                "'sha256-DAeySQs0Bz6D4fu31UbP2iNqPgR0Pu5/YT1PqjjfLpQ='",
                "'sha256-4P0GD04J+Fsjn5ASAw/vd24OT6m/QoU9v45tLQuETn4='",
                "'sha256-tSk08CtdW9H7HYasiQ2sopmrlMYNHHatAwu2HST9th4='",
                "'sha256-dAq46kYFOSmfb3zmhivow9XTBhA7IAKOO8ZRRBrXi+k='",
                "'sha256-HaL8rYJcfgdDNNFRcFQyQKTNdtJoiIIAAfbyydKmzGc='",
            ]),
            "style-src 'self' 'unsafe-inline'",
            'img-src * data: blob:',
            "media-src 'self' data: blob:",
            "font-src 'self' data:",
            "connect-src 'self' blob: https://pixabay.com",
            "worker-src 'self' blob:",
            "frame-src 'none'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
        ]);
    }

    private function removeFixtures(): void
    {
        $this->deleteUserByName(self::USERNAME);
        $asset = \Pimcore\Model\Asset::getByPath('/' . self::ASSET_KEY);
        if ($asset instanceof \Pimcore\Model\Asset) {
            $asset->delete();
        }
    }
}
