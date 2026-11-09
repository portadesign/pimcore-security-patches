<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-5394')]
final class CompositeIndexTest extends \PHPUnit\Framework\TestCase
{
    private const TABLE = 'pd_sec_composite_scratch';

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

    /**
     * @return array<string, array{string}>
     */
    public static function invalidIdentifierProvider(): array
    {
        return [
            'backtick' => ['a`b'],
            'semicolon' => ['a;b'],
            'space' => ['a b'],
            'leading digit' => ['1abc'],
            'trailing newline' => ["name\n"],
            'empty' => [''],
            'too long' => [str_repeat('a', 65)],
            'column breakout from advisory' => ['a), DROP COLUMN `c` -- '],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidKeyProvider(): array
    {
        return [
            'backtick' => ['a`b'],
            'semicolon' => ['a;b'],
            'space' => ['a b'],
            'comma' => ['a,b'],
            'parenthesis' => ['a(b'],
            'trailing newline' => ["abc\n"],
            'too long' => [str_repeat('a', 65)],
            'column breakout from advisory' => ['a), DROP COLUMN `c` -- '],
            'key breakout' => ['k` (a), DROP COLUMN `c`, ADD INDEX `z'],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validKeyProvider(): array
    {
        return [
            'letters' => ['abc'],
            'leading digit' => ['1abc'],
            'leading underscore' => ['_abc'],
            'leading dash' => ['-abc'],
            'plus' => ['a+b'],
            'maximum length' => [str_repeat('a', 64)],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function databaseKeyProvider(): array
    {
        return [
            'leading digit' => ['1abc'],
            'leading underscore' => ['_abc'],
            'leading dash' => ['-abc'],
            'plus' => ['a+b'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidIdentifierProvider')]
    public function testIndexColumnWithInvalidIdentifierIsRejected(string $column): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->classDao()->updateCompositeIndices(self::TABLE, 'query', [$this->index('poc_idx', [$column])]);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidKeyProvider')]
    public function testIndexKeyWithInvalidIdentifierIsRejected(string $key): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->classDao()->updateCompositeIndices(self::TABLE, 'query', [$this->index($key, ['a'])]);
    }

    /**
     * @return array<string, array{mixed}>
     */
    public static function nonStringIdentifierProvider(): array
    {
        $stringable = new class() implements \Stringable {
            public function __toString(): string
            {
                return 'a';
            }
        };

        return [
            'array' => [['a']],
            'stringable object' => [$stringable],
            'integer' => [5],
            'null' => [null],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('nonStringIdentifierProvider')]
    public function testIndexColumnThatIsNotAStringIsRejected(mixed $column): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->classDao()->updateCompositeIndices(self::TABLE, 'query', [$this->index('poc_idx', [$column])]);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('nonStringIdentifierProvider')]
    public function testIndexKeyThatIsNotAStringIsRejected(mixed $key): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->classDao()->updateCompositeIndices(self::TABLE, 'query', [$this->index($key, ['a'])]);
    }

    public function testIdentifiersNeedingQuotesAreQuotedWhenIndexIsCreatedAndDropped(): void
    {
        $table = 'pd_sec_composite-dash_scratch';
        $this->db->executeStatement('DROP TABLE IF EXISTS `' . $table . '`');
        $this->db->executeStatement('CREATE TABLE `' . $table . '` (oo_id INT NOT NULL PRIMARY KEY, a VARCHAR(20), `my-col` VARCHAR(20))');

        try {
            $dao = $this->classDao();

            $dao->updateCompositeIndices($table, 'query', [$this->index('k-1', ['my-col', 'a'])]);

            $this->assertSame(['my-col', 'a'], $this->indexColumns('c_k-1', $table));

            $dao->updateCompositeIndices($table, 'query', []);

            $this->assertSame([], $this->indexColumns('c_k-1', $table));
        } finally {
            $this->db->executeStatement('DROP TABLE IF EXISTS `' . $table . '`');
        }
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('validKeyProvider')]
    public function testControlClassDefinitionAcceptsLegacyIndexKeyOnAssignment(string $key): void
    {
        $class = (new \Pimcore\Model\DataObject\ClassDefinition())->setCompositeIndices([$this->index($key, ['a'])]);

        $this->assertSame($key, $class->getCompositeIndices()[0]['index_key']);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('databaseKeyProvider')]
    public function testControlLegacyIndexKeyIsCreatedAndDroppedAgain(string $key): void
    {
        $dao = $this->classDao();

        $dao->updateCompositeIndices(self::TABLE, 'query', [$this->index($key, ['a'])]);

        $this->assertSame(['a'], $this->indexColumns('c_' . $key));

        $dao->updateCompositeIndices(self::TABLE, 'query', []);

        $this->assertSame([], $this->indexColumns('c_' . $key));
    }

    public function testColumnInjectionDoesNotAlterTableSchema(): void
    {
        try {
            $this->classDao()->updateCompositeIndices(
                self::TABLE,
                'query',
                [$this->index('poc_idx', ['a), DROP COLUMN `c` -- '])],
            );
        } catch (\Throwable) {
        }

        $this->assertSame(['oo_id', 'a', 'b', 'c'], $this->columnNames());
    }

    public function testKeyInjectionDoesNotAlterTableSchema(): void
    {
        try {
            $this->classDao()->updateCompositeIndices(
                self::TABLE,
                'query',
                [$this->index('k` (a), DROP COLUMN `c`, ADD INDEX `z', ['a'])],
            );
        } catch (\Throwable) {
        }

        $this->assertSame(['oo_id', 'a', 'b', 'c'], $this->columnNames());
    }

    public function testControlValidIndexIsCreatedWithColumnsInOrderAndDroppedAgain(): void
    {
        $dao = $this->classDao();

        $dao->updateCompositeIndices(self::TABLE, 'query', [$this->index('my-index_1', ['b', 'a'])]);

        $this->assertSame(['b', 'a'], $this->indexColumns('c_my-index_1'));

        $dao->updateCompositeIndices(self::TABLE, 'query', []);

        $this->assertSame([], $this->indexColumns('c_my-index_1'));
    }

    /**
     * @param list<mixed> $columns
     *
     * @return array{index_key: mixed, index_type: string, index_columns: list<mixed>}
     */
    private function index(mixed $key, array $columns): array
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
    private function indexColumns(string $indexName, string $table = self::TABLE): array
    {
        $rows = $this->db->fetchAllAssociative(
            'SHOW INDEXES FROM `' . $table . '` WHERE Key_name = ?',
            [$indexName],
        );
        usort($rows, static fn (array $left, array $right): int => (int) $left['Seq_in_index'] <=> (int) $right['Seq_in_index']);

        return array_map(static fn (array $row): string => (string) $row['Column_name'], $rows);
    }
}
