<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

final class CustomReportsHardeningTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\ReportScratchTable;

    protected function setUp(): void
    {
        $this->createReportScratchTable();
    }

    protected function tearDown(): void
    {
        $this->dropReportScratchTable();
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function fileConstructProvider(): array
    {
        return [
            'into outfile in where' => ['where', "1 = 1 INTO OUTFILE '/tmp/pd-sec-out'"],
            'into dumpfile in sql' => ['sql', "id INTO DUMPFILE '/tmp/pd-sec-out'"],
            'into outfile split by newline in from' => ['from', "pd_sec_report_scratch INTO\nOUTFILE '/tmp/pd-sec-out'"],
            'lowercase into outfile in groupby' => ['groupby', 'id into   outfile "/tmp/pd-sec-out"'],
            'load_file in where' => ['where', "id = 1 AND LOAD_FILE('/etc/hostname') IS NOT NULL"],
            'load_file with space in sql' => ['sql', "id, LOAD_FILE ('/etc/hostname') AS probe"],
        ];
    }

    #[\PHPUnit\Framework\Attributes\Group('CVE-2026-55416')]
    #[\PHPUnit\Framework\Attributes\DataProvider('fileConstructProvider')]
    public function testGetDataRejectsFileConstruct(string $key, string $fragment): void
    {
        $adapter = $this->reportAdapter($this->reportConfig([$key => $fragment]));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/^Unsafe "' . $key . '" SQL fragment: construct /');

        $adapter->getData([], null, null, 0, 10);
    }

    #[\PHPUnit\Framework\Attributes\Group('CVE-2026-55416')]
    #[\PHPUnit\Framework\Attributes\DataProvider('fileConstructProvider')]
    public function testGetColumnsRejectsFileConstruct(string $key, string $fragment): void
    {
        $config = $this->reportConfig([$key => $fragment]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/^Unsafe "' . $key . '" SQL fragment: construct /');

        $this->reportAdapter($config)->getColumns($config);
    }

    #[\PHPUnit\Framework\Attributes\Group('CVE-2026-55416')]
    public function testQuotedFileConstructsAreNotTreatedAsUnsafe(): void
    {
        $config = $this->reportConfig([
            'sql' => 'id, note AS `into outfile`',
            'where' => "note = 'into outfile' OR note = \"load_file(x)\" OR id = 5",
        ]);

        $result = $this->reportAdapter($config)->getData([], 'id', 'ASC', 0, 10);

        $this->assertSame(['id', 'into outfile'], $this->reportAdapter($config)->getColumns($config));
        $this->assertSame(1, (int) $result['total']);
    }

    /**
     * @return array<string, array{callable(\Pimcore\Model\Tool\CustomReport\Adapter\Sql): mixed}>
     */
    public static function injectedIdentifierProvider(): array
    {
        return [
            'field list entry' => [static fn (\Pimcore\Model\Tool\CustomReport\Adapter\Sql $adapter): array => $adapter->getData(
                [],
                null,
                null,
                0,
                10,
                ['id`, (SELECT MAX(secret) FROM pd_sec_report_scratch) AS `leak'],
            )],
            'filter property' => [static fn (\Pimcore\Model\Tool\CustomReport\Adapter\Sql $adapter): array => $adapter->getData(
                [['type' => 'string', 'operator' => 'like', 'property' => 'note` LIKE \'%\' OR `id', 'value' => 'x']],
                null,
                null,
                0,
                10,
            )],
            'sort key' => [static fn (\Pimcore\Model\Tool\CustomReport\Adapter\Sql $adapter): array => $adapter->getData(
                [],
                'id` DESC, (SELECT 1) -- ',
                'ASC',
                0,
                10,
            )],
            'drill down key' => [static fn (\Pimcore\Model\Tool\CustomReport\Adapter\Sql $adapter): array => $adapter->getData(
                [],
                null,
                null,
                0,
                10,
                null,
                ['id` = 1 OR `id' => '1'],
            )],
            'available options field' => [static fn (\Pimcore\Model\Tool\CustomReport\Adapter\Sql $adapter): array => $adapter->getAvailableOptions(
                [],
                'note`, (SELECT MAX(secret) FROM pd_sec_report_scratch) AS `leak',
                [],
            )],
        ];
    }

    /**
     * @param callable(\Pimcore\Model\Tool\CustomReport\Adapter\Sql): mixed $call
     */
    #[\PHPUnit\Framework\Attributes\Group('CVE-2026-55416')]
    #[\PHPUnit\Framework\Attributes\DataProvider('injectedIdentifierProvider')]
    public function testIdentifierWithBacktickIsRejected(callable $call): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException('Invalid field name.'));

        $call($this->reportAdapter($this->reportConfig()));
    }

    #[\PHPUnit\Framework\Attributes\Group('CVE-2026-55416')]
    public function testLegitimateFieldListFilterAndSortStillWork(): void
    {
        $config = $this->reportConfig(['sql' => 'id, note AS `My Note`, updated_at']);
        $adapter = $this->reportAdapter($config);

        $listed = $adapter->getData([], 'id', 'DESC', 0, 2, ['id', 'My Note']);
        $filtered = $adapter->getData(
            [['type' => 'string', 'operator' => 'like', 'property' => 'My Note', 'value' => 'plain']],
            null,
            null,
            0,
            10,
        );
        $options = $adapter->getAvailableOptions([], 'My Note', []);

        $this->assertSame([['id' => 5, 'My Note' => 'plain'], ['id' => 4, 'My Note' => 'c /* x */']], $this->normalizeRows($listed['data']));
        $this->assertSame([5], array_map('intval', array_column($filtered['data'], 'id')));
        $this->assertContains('plain', array_column($options['data'], 'value'));
    }

    #[\PHPUnit\Framework\Attributes\Group('CVE-2026-44739')]
    public function testBacktickQuotedKeywordIdentifiersStillRun(): void
    {
        $config = $this->reportConfig(['sql' => 'id AS `update`, note AS `delete`', 'where' => 'id = 3']);

        $this->assertSame(['update', 'delete'], $this->reportAdapter($config)->getColumns($config));
    }

    #[\PHPUnit\Framework\Attributes\Group('CVE-2026-44739')]
    public function testKeywordAfterQuotedIdentifierIsStillRefused(): void
    {
        $config = $this->reportConfig(['sql' => 'id AS `update`, drop x', 'from' => '']);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessageMatches("/^Only 'SELECT' statements are allowed! You've used 'DROP'/");

        $this->reportAdapter($config)->getColumns($config);
    }

    /**
     * @param list<array<string, mixed>> $rows
     *
     * @return list<array<string, int|string>>
     */
    private function normalizeRows(array $rows): array
    {
        return array_map(
            static fn (array $row): array => array_map(
                static fn (mixed $value): int|string => is_numeric($value) ? (int) $value : (string) $value,
                $row,
            ),
            $rows,
        );
    }
}
