<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-45704')]
final class CustomReportsShareTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P4ReportScratchTable;

    private const REPORT_PREFIX = 'pd-sec-share-report-';

    private const SCOPE = 'pimcore_custom_reports';

    private const USERNAME = 'pd-sec-share-user';

    private const OTHER_USERNAME = 'pd-sec-share-other';

    private const ROLE = 'pd-sec-share-role';

    private const OTHER_ROLE = 'pd-sec-share-other-role';

    private const FOREIGN_CONTENT = "pd-sec-foreign-secret\n";

    private \Pimcore\Model\User $user;

    private \Pimcore\Model\User $otherUser;

    private \Pimcore\Model\User\Role $role;

    private \Pimcore\Model\User\Role $otherRole;

    private string $reportName;

    /**
     * @var list<string>
     */
    private array $exportFiles = [];

    /**
     * @var list<string>
     */
    private array $preexistingExports = [];

    public static function setUpBeforeClass(): void
    {
        require_once __DIR__ . '/Support/P4CsvFormulaFormatterShim.php';
    }

    protected function setUp(): void
    {
        $this->preexistingExports = glob(PIMCORE_SYSTEM_TEMP_DIRECTORY . '/*.csv') ?: [];
        $this->removeFixtures();
        $this->createReportScratchTable();
        $this->reportName = self::REPORT_PREFIX . bin2hex(random_bytes(4));

        $this->role = \Pimcore\Model\User\Role::create(['parentId' => 0, 'name' => self::ROLE]);
        $this->otherRole = \Pimcore\Model\User\Role::create(['parentId' => 0, 'name' => self::OTHER_ROLE]);

        $this->user = $this->createUser(self::USERNAME, ['reports'], [$this->role->getId()]);
        $this->otherUser = $this->createUser(self::OTHER_USERNAME, ['reports'], []);

        $this->authenticate($this->user);
    }

    protected function tearDown(): void
    {
        $this->authenticate(null);

        try {
            $this->removeFixtures();
        } finally {
            $this->dropReportScratchTable();
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function actionProvider(): array
    {
        return [
            'get' => ['get'],
            'data' => ['data'],
            'chart' => ['chart'],
            'drill-down options' => ['drillDownOptions'],
            'create csv' => ['createCsv'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('actionProvider')]
    public function testUnsharedReportIsForbidden(string $action): void
    {
        $this->createReport(shareGlobally: false, userNames: [self::OTHER_USERNAME], roleNames: [self::OTHER_ROLE]);

        $this->expectException(\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException::class);

        $this->call($action);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('actionProvider')]
    public function testReportWithoutAnySharingIsForbidden(string $action): void
    {
        $this->createReport(shareGlobally: false);

        $this->expectException(\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException::class);

        $this->call($action);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('actionProvider')]
    public function testControlReportSharedWithUserIsAccessible(string $action): void
    {
        $this->createReport(shareGlobally: false, userNames: [self::USERNAME]);

        $this->assertSame(200, $this->call($action)->getStatusCode());
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('actionProvider')]
    public function testControlReportSharedWithRoleOfUserIsAccessible(string $action): void
    {
        $this->createReport(shareGlobally: false, roleNames: [self::OTHER_ROLE, self::ROLE]);

        $this->assertSame(200, $this->call($action)->getStatusCode());
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('actionProvider')]
    public function testControlReportSharedGloballyIsAccessible(string $action): void
    {
        $this->createReport(shareGlobally: true);

        $this->assertSame(200, $this->call($action)->getStatusCode());
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('actionProvider')]
    public function testControlAdminAccessesUnsharedReport(string $action): void
    {
        $admin = $this->createUser('pd-sec-share-admin', [], [], true);
        $this->authenticate($admin);
        $this->createReport(shareGlobally: false, userNames: [self::OTHER_USERNAME]);

        $this->assertSame(200, $this->call($action)->getStatusCode());
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('actionProvider')]
    public function testControlReportEditorAccessesUnsharedReport(string $action): void
    {
        $this->user->setPermissions(['reports', 'reports_config']);
        $this->user->save();
        $this->authenticate($this->user);
        $this->createReport(shareGlobally: false, userNames: [self::OTHER_USERNAME]);

        $this->assertSame(200, $this->call($action)->getStatusCode());
    }

    public function testControlReportEditorWithoutReportsPermissionStillReadsUnsharedReport(): void
    {
        $this->user->setPermissions(['reports_config']);
        $this->user->save();
        $this->authenticate($this->user);
        $this->createReport(shareGlobally: false, userNames: [self::OTHER_USERNAME]);

        $this->assertSame(200, $this->call('get')->getStatusCode());
    }

    public function testControlListingOmitsUnsharedReport(): void
    {
        $this->createReport(shareGlobally: false, userNames: [self::OTHER_USERNAME]);

        $this->assertNotContains($this->reportName, $this->listedReportNames());
    }

    public function testControlListingContainsSharedReport(): void
    {
        $this->createReport(shareGlobally: false, userNames: [self::USERNAME]);

        $this->assertContains($this->reportName, $this->listedReportNames());
    }

    public function testControlListingContainsReportSharedWithRole(): void
    {
        $this->createReport(shareGlobally: false, roleNames: [self::ROLE]);

        $this->assertContains($this->reportName, $this->listedReportNames());
    }

    public function testControlUnknownReportIsNotFound(): void
    {
        $this->expectException(\Symfony\Component\HttpKernel\Exception\NotFoundHttpException::class);

        $this->call('get');
    }

    public function testControlSharedCsvExportContainsRows(): void
    {
        $this->createReport(shareGlobally: false, userNames: [self::USERNAME]);

        $response = $this->call('createCsv');

        $this->assertSame(200, $response->getStatusCode());
        $csv = (string) file_get_contents(PIMCORE_SYSTEM_TEMP_DIRECTORY . '/' . basename(end($this->exportFiles)));

        $this->assertStringContainsString('plain', $csv);
    }

    public function testForbiddenCsvExportWritesNoFile(): void
    {
        $this->createReport(shareGlobally: false, userNames: [self::OTHER_USERNAME]);
        $before = glob(PIMCORE_SYSTEM_TEMP_DIRECTORY . '/report-export-*.csv') ?: [];

        try {
            $this->call('createCsv');
            $this->fail('Unshared report was exported.');
        } catch (\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException) {
        }

        $this->assertSame($before, glob(PIMCORE_SYSTEM_TEMP_DIRECTORY . '/report-export-*.csv') ?: []);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function foreignExportProvider(): array
    {
        return [
            'export of another user' => ['export-of-another-user'],
            'planted csv' => ['planted'],
            'export name without user id' => ['legacy-name'],
            'user id that only starts with the own id' => ['id-prefix'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('foreignExportProvider')]
    public function testDownloadOfForeignCsvIsDenied(string $kind): void
    {
        $this->createReport(shareGlobally: true);
        $name = $this->plantForeignCsv($kind);

        $this->assertDenied(fn () => $this->downloadCsv($name));
        $this->assertSame(self::FOREIGN_CONTENT, file_get_contents($this->exportPath($name)));
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('foreignExportProvider')]
    public function testContinuingForeignCsvIsDeniedAndLeavesItUntouched(string $kind): void
    {
        $this->createReport(shareGlobally: true);
        $name = $this->plantForeignCsv($kind);

        $this->assertDenied(fn () => $this->createCsvExport(['exportFile' => $name]));
        $this->assertSame(self::FOREIGN_CONTENT, file_get_contents($this->exportPath($name)));
    }

    public function testControlOwnExportCanBeDownloaded(): void
    {
        $this->createReport(shareGlobally: true);
        $name = $this->createCsvExport();

        $response = $this->downloadCsv($name);

        $this->assertSame(realpath($this->exportPath($name)), $response->getFile()->getRealPath());
        $this->assertStringContainsString('plain', (string) file_get_contents($this->exportPath($name)));
    }

    public function testControlOwnExportCanBeContinued(): void
    {
        $this->createReport(shareGlobally: true);
        $name = $this->createCsvExport();

        $this->assertSame($name, $this->createCsvExport(['exportFile' => $name]));
        $this->assertSame(2, substr_count((string) file_get_contents($this->exportPath($name)), 'plain'));
    }

    private function call(string $action): \Symfony\Component\HttpFoundation\JsonResponse
    {
        $controller = $this->controller();

        $response = match ($action) {
            'get' => $controller->getAction(new \Symfony\Component\HttpFoundation\Request(['name' => $this->reportName])),
            'data' => $controller->dataAction($this->post(['name' => $this->reportName, 'start' => 0, 'limit' => 10])),
            'chart' => $controller->chartAction($this->post(['name' => $this->reportName])),
            'drillDownOptions' => $controller->drillDownOptionsAction($this->post(['name' => $this->reportName, 'field' => 'note'])),
            'createCsv' => $controller->createCsvAction(new \Symfony\Component\HttpFoundation\Request(['name' => $this->reportName, 'headers' => 1, 'drillDownFilters' => '[]'])),
        };

        if ('createCsv' === $action) {
            $payload = json_decode((string) $response->getContent(), true, 512, JSON_THROW_ON_ERROR);
            $this->exportFiles[] = $payload['exportFile'];
        }

        return $response;
    }

    private function plantForeignCsv(string $kind): string
    {
        $name = match ($kind) {
            'export-of-another-user' => $this->exportOfOtherUser(),
            'planted' => 'pd-sec-planted-' . bin2hex(random_bytes(4)) . '.csv',
            'legacy-name' => 'report-export-pdsec' . bin2hex(random_bytes(4)) . '.csv',
            'id-prefix' => 'report-export-' . $this->user->getId() . '0-pdsec' . bin2hex(random_bytes(4)) . '.csv',
        };

        file_put_contents($this->exportPath($name), self::FOREIGN_CONTENT);
        $this->exportFiles[] = $name;

        return $name;
    }

    private function exportOfOtherUser(): string
    {
        $this->authenticate($this->otherUser);
        $name = $this->createCsvExport();
        $this->authenticate($this->user);

        return $name;
    }

    /**
     * @param array<string, mixed> $extra
     */
    private function createCsvExport(array $extra = []): string
    {
        $response = $this->controller()->createCsvAction(new \Symfony\Component\HttpFoundation\Request(array_merge(
            ['name' => $this->reportName, 'headers' => 1, 'drillDownFilters' => '[]'],
            $extra,
        )));
        $payload = json_decode((string) $response->getContent(), true, 512, JSON_THROW_ON_ERROR);
        $this->exportFiles[] = $payload['exportFile'];

        return $payload['exportFile'];
    }

    private function downloadCsv(string $name): \Symfony\Component\HttpFoundation\BinaryFileResponse
    {
        return $this->controller()->downloadCsvAction(new \Symfony\Component\HttpFoundation\Request(['exportFile' => $name]));
    }

    private function exportPath(string $name): string
    {
        return PIMCORE_SYSTEM_TEMP_DIRECTORY . '/' . $name;
    }

    private function assertDenied(callable $action): void
    {
        try {
            $action();
        } catch (\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException | \Symfony\Component\Security\Core\Exception\InvalidArgumentException) {
            return;
        }

        $this->fail('Access to a csv file of another user was granted.');
    }

    /**
     * @param array<string, mixed> $parameters
     */
    private function post(array $parameters): \Symfony\Component\HttpFoundation\Request
    {
        $request = new \Symfony\Component\HttpFoundation\Request(request: $parameters);
        $request->setMethod('POST');

        return $request;
    }

    private function controller(): \Pimcore\Bundle\AdminBundle\Controller\Reports\CustomReportController
    {
        $container = \Pimcore::getContainer();

        $controller = new \Pimcore\Bundle\AdminBundle\Controller\Reports\CustomReportController();
        $controller->setContainer($container);
        $controller->setTokenResolver($container->get(\Pimcore\Security\User\TokenStorageUserResolver::class));
        $controller->setPimcoreSerializer($container->get(\Pimcore\Serializer\Serializer::class));

        return $controller;
    }

    /**
     * @return list<string>
     */
    private function listedReportNames(): array
    {
        $response = $this->controller()->getReportConfigAction(new \Symfony\Component\HttpFoundation\Request());
        $payload = json_decode((string) $response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        return array_column($payload['reports'], 'name');
    }

    /**
     * @param list<string> $userNames
     * @param list<string> $roleNames
     */
    private function createReport(bool $shareGlobally, array $userNames = [], array $roleNames = []): void
    {
        $now = time();

        \Pimcore\Model\Tool\SettingsStore::set(
            $this->reportName,
            json_encode([
                'name' => $this->reportName,
                'niceName' => 'pd-sec share report',
                'dataSourceConfig' => [['type' => 'sql', 'sql' => 'id, note', 'from' => $this->reportTable(), 'where' => '', 'groupby' => '']],
                'columnConfiguration' => [
                    ['name' => 'id', 'display' => true, 'export' => true, 'order' => true, 'label' => 'id'],
                    ['name' => 'note', 'display' => true, 'export' => true, 'order' => true, 'label' => 'note'],
                ],
                'shareGlobally' => $shareGlobally,
                'sharedUserNames' => $userNames,
                'sharedRoleNames' => $roleNames,
                'menuShortcut' => false,
                'creationDate' => $now,
                'modificationDate' => $now,
            ], JSON_THROW_ON_ERROR),
            'string',
            self::SCOPE,
        );
    }

    /**
     * @param list<string> $permissions
     * @param list<int> $roleIds
     */
    private function createUser(string $name, array $permissions, array $roleIds, bool $admin = false): \Pimcore\Model\User
    {
        $user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => $name,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
            'admin' => $admin,
        ]);
        $user->setPermissions($permissions);
        $user->setRoles($roleIds);
        $user->save();

        return $user;
    }

    private function removeFixtures(): void
    {
        foreach ($this->exportFiles as $file) {
            @unlink(PIMCORE_SYSTEM_TEMP_DIRECTORY . '/' . basename($file));
        }
        $this->exportFiles = [];

        foreach (array_diff(glob(PIMCORE_SYSTEM_TEMP_DIRECTORY . '/*.csv') ?: [], $this->preexistingExports) as $file) {
            @unlink($file);
        }

        foreach (\Pimcore\Model\Tool\SettingsStore::getIdsByScope(self::SCOPE) as $id) {
            if (str_starts_with($id, self::REPORT_PREFIX)) {
                \Pimcore\Model\Tool\SettingsStore::delete($id, self::SCOPE);
            }
        }

        foreach ([self::USERNAME, self::OTHER_USERNAME, 'pd-sec-share-admin'] as $name) {
            $this->deleteUserByName($name);
        }

        foreach ([self::ROLE, self::OTHER_ROLE] as $name) {
            $role = \Pimcore\Model\User\Role::getByName($name);
            $role?->delete();
        }
    }
}
