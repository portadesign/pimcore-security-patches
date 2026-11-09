<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-23493')]
final class HttpErrorLogTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;

    private const URI_PREFIX = 'http://pd-sec-23493.example/missing-';

    private const ADMIN_USERNAME = 'pd-sec-http-error-log-admin';

    /**
     * @var array<string, mixed>
     */
    private array $originalCookie = [];

    /**
     * @var array<string, mixed>
     */
    private array $originalServer = [];

    /**
     * @var array<string, mixed>
     */
    private array $originalGet = [];

    /**
     * @var array<string, mixed>
     */
    private array $originalPost = [];

    private string $uri = '';

    protected function setUp(): void
    {
        $this->originalCookie = $_COOKIE;
        $this->originalServer = $_SERVER;
        $this->originalGet = $_GET;
        $this->originalPost = $_POST;
        $this->uri = self::URI_PREFIX . bin2hex(random_bytes(4));
    }

    protected function tearDown(): void
    {
        $_COOKIE = $this->originalCookie;
        $_SERVER = $this->originalServer;
        $_GET = $this->originalGet;
        $_POST = $this->originalPost;
        $this->authenticate(null);
        $this->deleteUserByName(self::ADMIN_USERNAME);
        \Pimcore\Db::get()->executeStatement('DELETE FROM http_error_log WHERE uri LIKE ?', [self::URI_PREFIX . '%']);
    }

    public function testNewErrorLogRowStoresNeitherCookiesNorServerVariables(): void
    {
        $_COOKIE['PHPSESSID'] = 's3cret-session';
        $_SERVER['PD_SECRET'] = 'x-secret-environment';

        $this->log();
        $row = $this->row();

        $this->assertSame(
            ['cookieCount' => 0, 'serverVarCount' => 0, 'secretInRow' => false],
            [
                'cookieCount' => count(unserialize($row['cookies'], ['allowed_classes' => false])),
                'serverVarCount' => count(unserialize($row['serverVars'], ['allowed_classes' => false])),
                'secretInRow' => str_contains($row['cookies'] . $row['serverVars'], 's3cret-session')
                    || str_contains($row['cookies'] . $row['serverVars'], 'x-secret-environment'),
            ],
        );
    }

    public function testControlRequestParametersAreStillLoggedAndRepeatedHitsAreCounted(): void
    {
        $_GET = ['q' => 'term'];
        $_POST = ['field' => 'value'];

        $this->log();
        $this->log();
        $row = $this->row();

        $this->assertSame(
            ['parametersGet' => ['q' => 'term'], 'parametersPost' => ['field' => 'value'], 'code' => '404', 'count' => '2'],
            [
                'parametersGet' => unserialize($row['parametersGet'], ['allowed_classes' => false]),
                'parametersPost' => unserialize($row['parametersPost'], ['allowed_classes' => false]),
                'code' => (string) $row['code'],
                'count' => (string) $row['count'],
            ],
        );
    }

    public function testDetailViewOfLegacyRowDoesNotShowStoredCookiesOrServerVariables(): void
    {
        \Pimcore\Db::get()->insert('http_error_log', [
            'uri' => $this->uri,
            'code' => 404,
            'parametersGet' => serialize(['pd-sec-get-key' => 'pd-sec-get-value']),
            'parametersPost' => serialize([]),
            'cookies' => serialize(['PHPSESSID' => 's3cret-legacy-session']),
            'serverVars' => serialize(['PD_SECRET' => 'x-legacy-environment']),
            'date' => time(),
            'count' => 1,
        ]);
        $this->authenticate($this->createAdmin());

        $content = (string) \Pimcore::getContainer()->get(\Pimcore\Bundle\AdminBundle\Controller\Admin\MiscController::class)
            ->httpErrorLogDetailAction(new \Symfony\Component\HttpFoundation\Request(['uri' => $this->uri]), null)
            ->getContent();

        $this->assertSame(
            ['session' => false, 'environment' => false, 'getParameter' => true],
            [
                'session' => str_contains($content, 's3cret-legacy-session'),
                'environment' => str_contains($content, 'x-legacy-environment'),
                'getParameter' => str_contains($content, 'pd-sec-get-value'),
            ],
        );
    }

    private function log(): void
    {
        $listener = (new \ReflectionClass(\Pimcore\Bundle\CoreBundle\EventListener\ResponseExceptionListener::class))->newInstanceWithoutConstructor();
        (new \ReflectionProperty($listener, 'db'))->setValue($listener, \Pimcore\Db::get());
        $request = \Symfony\Component\HttpFoundation\Request::create($this->uri);

        (new \ReflectionMethod($listener, 'logToHttpErrorLog'))->invoke($listener, $request, 404);
    }

    /**
     * @return array<string, mixed>
     */
    private function row(): array
    {
        $row = \Pimcore\Db::get()->fetchAssociative('SELECT * FROM http_error_log WHERE uri = ?', [$this->uri]);
        $this->assertIsArray($row, 'No http_error_log row was written for ' . $this->uri);

        return $row;
    }

    private function createAdmin(): \Pimcore\Model\User
    {
        $this->deleteUserByName(self::ADMIN_USERNAME);

        return \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::ADMIN_USERNAME,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => false,
            'admin' => true,
        ]);
    }
}
