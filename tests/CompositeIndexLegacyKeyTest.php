<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-5394')]
final class CompositeIndexLegacyKeyTest extends \PHPUnit\Framework\TestCase
{
    private const TABLE = 'pd_sec_composite_legacy_scratch';

    private \Doctrine\DBAL\Connection $db;

    protected function setUp(): void
    {
        $this->db = \Pimcore\Db::get();
        $this->db->executeStatement('DROP TABLE IF EXISTS `' . self::TABLE . '`');
        $this->db->executeStatement('CREATE TABLE `' . self::TABLE . '` (oo_id INT NOT NULL PRIMARY KEY, a VARCHAR(20), b VARCHAR(20), c VARCHAR(20))');
    }

    protected function tearDown(): void
    {
        $this->db->executeStatement('DROP TABLE IF EXISTS `' . self::TABLE . '`');
    }

    public function testControlDefinitionWithEmptyIndexKeyStillLoads(): void
    {
        $class = \Pimcore\Model\DataObject\ClassDefinition::__set_state([
            'name' => 'PdSecLegacy',
            'compositeIndices' => [$this->index('', ['a'])],
        ]);

        $this->assertCount(1, $class->getCompositeIndices());
        $this->assertSame('', $class->getCompositeIndices()[0]['index_key']);
    }

    public function testControlDefinitionWithHostileIndexKeyStillLoads(): void
    {
        $key = 'k` (a), DROP COLUMN `c`, ADD INDEX `z';

        $class = \Pimcore\Model\DataObject\ClassDefinition::__set_state([
            'name' => 'PdSecLegacy',
            'compositeIndices' => [$this->index($key, ['a'])],
        ]);

        $this->assertSame($key, $class->getCompositeIndices()[0]['index_key']);
    }

    public function testSavingEmptyIndexKeyExecutesNoSqlForThatIndex(): void
    {
        $this->db->executeStatement('ALTER TABLE `' . self::TABLE . '` ADD INDEX `c_` (b)');

        $this->classDao()->updateCompositeIndices(self::TABLE, 'query', [$this->index('', ['a'])]);

        $this->assertSame(['b'], $this->indexColumns('c_'));
    }

    public function testInjectedColumnIsStillRejectedNextToEmptyKey(): void
    {
        try {
            $this->classDao()->updateCompositeIndices(
                self::TABLE,
                'query',
                [$this->index('', ['a']), $this->index('poc_idx', ['a), DROP COLUMN `c` -- '])],
            );
            $this->fail('Injected column was accepted.');
        } catch (\InvalidArgumentException) {
            $this->assertSame(['oo_id', 'a', 'b', 'c'], $this->columnNames());
        }
    }

    public function testInjectedKeyIsStillRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->classDao()->updateCompositeIndices(
            self::TABLE,
            'query',
            [$this->index('k` (a), DROP COLUMN `c`, ADD INDEX `z', ['a'])],
        );
    }

    /**
     * @param list<string> $columns
     *
     * @return array{index_key: string, index_type: string, index_columns: list<string>}
     */
    private function index(string $key, array $columns): array
    {
        return ['index_key' => $key, 'index_type' => 'query', 'index_columns' => $columns];
    }

    private function classDao(): \Pimcore\Model\DataObject\ClassDefinition\Dao
    {
        $dao = (new \Pimcore\Model\DataObject\ClassDefinition())->getDao();
        \assert($dao instanceof \Pimcore\Model\DataObject\ClassDefinition\Dao);

        return $dao;
    }

    /**
     * @return list<string>
     */
    private function columnNames(): array
    {
        return array_map(
            static fn (array $row): string => (string) $row['Field'],
            $this->db->fetchAllAssociative('SHOW COLUMNS FROM `' . self::TABLE . '`'),
        );
    }

    /**
     * @return list<string>
     */
    private function indexColumns(string $indexName): array
    {
        $rows = $this->db->fetchAllAssociative(
            'SHOW INDEXES FROM `' . self::TABLE . '` WHERE Key_name = ?',
            [$indexName],
        );
        usort($rows, static fn (array $left, array $right): int => (int) $left['Seq_in_index'] <=> (int) $right['Seq_in_index']);

        return array_map(static fn (array $row): string => (string) $row['Column_name'], $rows);
    }
}
