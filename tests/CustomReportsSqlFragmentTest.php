<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-55416')]
final class CustomReportsSqlFragmentTest extends \PHPUnit\Framework\TestCase
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
    public static function unsafeFragmentProvider(): array
    {
        return [
            'semicolon in sql' => ['sql', 'id; SELECT 1'],
            'comment dash in sql' => ['sql', 'id -- trailing'],
            'hash comment in sql' => ['sql', 'id # trailing'],
            'block comment opener in sql' => ['sql', 'id /* x'],
            'block comment closer in sql' => ['sql', 'id */ x'],
            'semicolon in from' => ['from', 'pd_sec_report_scratch; SELECT 1'],
            'comment dash in from' => ['from', 'pd_sec_report_scratch -- x'],
            'hash comment in where' => ['where', '1 = 1 #'],
            'stacked update in where' => ['where', "id = 1; UPDATE pd_sec_report_scratch SET secret = 'pwned'"],
            'block comment in where' => ['where', 'id = 1 /**/ OR /**/ 1 = 1'],
            'semicolon in groupby' => ['groupby', 'id; SELECT 1'],
            'comment dash in groupby' => ['groupby', 'id -- x'],
            'leading drop in sql' => ['sql', 'DROP TABLE pd_sec_report_scratch'],
            'leading delete in sql' => ['sql', 'DELETE FROM pd_sec_report_scratch'],
            'leading update in sql' => ['sql', "UPDATE pd_sec_report_scratch SET secret = 'pwned'"],
            'leading insert in sql' => ['sql', 'INSERT INTO pd_sec_report_scratch VALUES (9, 1, 1, 1)'],
            'leading alter in sql' => ['sql', 'ALTER TABLE pd_sec_report_scratch ADD x INT'],
            'leading create in sql' => ['sql', 'CREATE TABLE pd_sec_report_created (a INT)'],
            'leading truncate in sql' => ['sql', 'TRUNCATE pd_sec_report_scratch'],
            'leading drop in where' => ['where', 'DROP TABLE pd_sec_report_scratch'],
            'backslash before quote hides stacked insert in where' => ['where', "'\\' ; INSERT INTO pd_sec_report_scratch VALUES (9, 1, 1, 1) -- '"],
            'backslash before quote hides stacked statement in sql' => ['sql', "'\\' ; DROP TABLE pd_sec_report_scratch -- '"],
            'backslash before double quote hides stacked statement in groupby' => ['groupby', '"\\" ; DROP TABLE pd_sec_report_scratch -- "'],
            'escaped quote then quote pair hides stacked drop in where' => ['where', "'\\'' ; DROP TABLE pd_sec_report_scratch"],
            'escaped quote then quote pair hides stacked drop in sql' => ['sql', "'\\'' ; DROP TABLE pd_sec_report_scratch"],
            'unterminated single quote in where' => ['where', "note = 'abc"],
            'unterminated double quote in sql' => ['sql', 'id, "abc'],
            'unterminated backtick in groupby' => ['groupby', '`note'],
            'trailing backslash inside quote in where' => ['where', "note = 'abc\\"],
            'leading replace into in sql' => ['sql', 'REPLACE INTO pd_sec_report_scratch VALUES (9, 1, 1, 1)'],
            'leading replace into in where' => ['where', 'REPLACE INTO pd_sec_report_scratch VALUES (9, 1, 1, 1)'],
            'leading insert into in where' => ['where', 'INSERT INTO pd_sec_report_scratch VALUES (9, 1, 1, 1)'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('unsafeFragmentProvider')]
    public function testGetDataRejectsUnsafeFragment(string $key, string $fragment): void
    {
        $adapter = $this->reportAdapter($this->reportConfig([$key => $fragment]));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/^Unsafe "' . $key . '" SQL fragment: /');

        $adapter->getData([], null, null, 0, 10);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('unsafeFragmentProvider')]
    public function testGetColumnsRejectsUnsafeFragment(string $key, string $fragment): void
    {
        $config = $this->reportConfig([$key => $fragment]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/^Unsafe "' . $key . '" SQL fragment: /');

        $this->reportAdapter($config)->getColumns($config);
    }

    public function testNonStringFragmentIsRejected(): void
    {
        $adapter = $this->reportAdapter($this->reportConfig(['where' => ['1 = 1']]));

        $this->expectExceptionObject(new \InvalidArgumentException('Invalid "where" SQL fragment; expected string.'));

        $adapter->getData([], null, null, 0, 10);
    }

    public function testLimitArgumentIsCastToIntegerRatherThanInterpolated(): void
    {
        $adapter = $this->reportAdapter($this->reportConfig(['sql' => 'id']));

        $result = $adapter->getData([], null, null, '0', '1 INTO @pd_sec_limit_marker');

        $this->assertCount(1, $result['data']);
    }

    #[\PHPUnit\Framework\Attributes\Group('CVE-2026-44739')]
    public function testAdvisoryStackedUpdatePayloadLeavesDataUntouched(): void
    {
        $payload = "id=1)/**/OR/**/1=1;/**/UPDATE/**/pd_sec_report_scratch/**/SET/**/secret='pwned'/**/WHERE/**/id=1;-- -";
        $config = $this->reportConfig(['sql' => '*', 'where' => $payload]);

        try {
            $this->reportAdapter($config)->getColumns($config);
        } catch (\Throwable) {
        }

        $this->assertSame(['original', 'original', 'original', 'original', 'original'], $this->storedSecrets());
    }

    public function testQuotedTokensAreNotTreatedAsUnsafe(): void
    {
        $where = "note = 'semi;colon' OR note = \"dash -- x\" OR note = 'hash # y' OR note = 'c /* x */'";
        $adapter = $this->reportAdapter($this->reportConfig(['where' => $where]));

        $result = $adapter->getData([], 'id', 'ASC', 0, 10);

        $this->assertSame([1, 2, 3, 4], array_map('intval', array_column($result['data'], 'id')));
        $this->assertSame(4, (int) $result['total']);
    }

    public function testEscapedAndDoubledQuotesInsideStringLiteralsAreNotTreatedAsUnsafe(): void
    {
        $where = "note = 'it\\'s' OR note = 'it''s' OR note = \"say \\\"hi\\\"\"";
        $adapter = $this->reportAdapter($this->reportConfig(['where' => $where]));

        $result = $adapter->getData([], 'id', 'ASC', 0, 10);

        $this->assertSame([], $result['data']);
        $this->assertSame(0, (int) $result['total']);
    }

    public function testKeywordSubstringsInIdentifiersAndFunctionsAreNotTreatedAsUnsafe(): void
    {
        $config = $this->reportConfig(['sql' => "id, updated_at, INSERT(note, 1, 2, 'xx') AS patched", 'where' => 'id = 5']);

        $result = $this->reportAdapter($config)->getData([], null, null, 0, 10);

        $this->assertSame([['id' => 5, 'updated_at' => 50, 'patched' => 'xxain']], $this->normalizeRows($result['data']));
        $this->assertSame(1, (int) $result['total']);
    }

    public function testLeadingReplaceFunctionIsNotTreatedAsStatement(): void
    {
        $config = $this->reportConfig(['sql' => "REPLACE(note, 'plain', 'x') AS replaced, id", 'where' => 'id = 5']);

        $result = $this->reportAdapter($config)->getData([], null, null, 0, 10);

        $this->assertSame([['replaced' => 'x', 'id' => 5]], $this->normalizeRows($result['data']));
        $this->assertSame(1, (int) $result['total']);
    }

    public function testLeadingInsertFunctionIsNotTreatedAsStatement(): void
    {
        $config = $this->reportConfig(['sql' => "INSERT(note, 1, 2, 'xx') AS patched, id", 'where' => 'id = 5']);

        $result = $this->reportAdapter($config)->getData([], null, null, 0, 10);

        $this->assertSame([['patched' => 'xxain', 'id' => 5]], $this->normalizeRows($result['data']));
        $this->assertSame(1, (int) $result['total']);
    }

    public function testConfiguredHostReportStillRuns(): void
    {
        $this->createFixtureReport();

        try {
            $report = \Pimcore\Model\Tool\CustomReport\Config::getByName(self::FIXTURE_REPORT_NAME);
            $this->assertInstanceOf(\Pimcore\Model\Tool\CustomReport\Config::class, $report);

            $dataSources = $report->getDataSourceConfig();
            $dataSources = is_array($dataSources) ? $dataSources : [$dataSources];
            $dataSource = $dataSources[0];

            $result = \Pimcore\Model\Tool\CustomReport\Config::getAdapter($dataSource, $report)->getData([], null, null, 0, 5);

            $this->assertSame(5, count($result['data']));
            $this->assertSame(5, (int) $result['total']);
        } finally {
            $this->removeFixtureReport();
        }
    }

    private const FIXTURE_REPORT_NAME = 'pd-sec-fixture-report';

    private function createFixtureReport(): void
    {
        $this->removeFixtureReport();

        $report = new \Pimcore\Model\Tool\CustomReport\Config();
        $report->setName(self::FIXTURE_REPORT_NAME);
        $report->setDataSourceConfig([(object) [
            'type' => 'sql',
            'sql' => 'id, note',
            'from' => $this->reportTable(),
            'where' => '',
            'groupby' => '',
        ]]);
        $report->save();
    }

    private function removeFixtureReport(): void
    {
        $report = \Pimcore\Model\Tool\CustomReport\Config::getByName(self::FIXTURE_REPORT_NAME);

        if ($report instanceof \Pimcore\Model\Tool\CustomReport\Config) {
            $report->delete();
        }
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
