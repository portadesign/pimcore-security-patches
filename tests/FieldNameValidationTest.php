<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-55634')]
final class FieldNameValidationTest extends \PHPUnit\Framework\TestCase
{
    private const TABLE = 'pd_sec_field_name_scratch';

    private \Doctrine\DBAL\Connection $db;

    protected function setUp(): void
    {
        $this->db = \Pimcore\Db::get();
        $this->db->executeStatement('DROP TABLE IF EXISTS `' . self::TABLE . '`');
    }

    protected function tearDown(): void
    {
        $this->db->executeStatement('DROP TABLE IF EXISTS `' . self::TABLE . '`');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidNameProvider(): array
    {
        return [
            'php injection' => ['foo;system()'],
            'property breakout' => ['poc; public function pd(){} private $z'],
            'constructor injection' => ['x;function __construct(){}//'],
            'backtick breakout' => ['poc` varchar(1), col `x'],
            'space' => ['a b'],
            'dash' => ['a-b'],
            'leading digit' => ['1field'],
            'newline' => ["field\nsecond"],
            'trailing newline' => ["field\n"],
            'dollar' => ['$field'],
            'too long' => [str_repeat('a', 64)],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validNameProvider(): array
    {
        return [
            'camel case' => ['myField'],
            'leading underscore' => ['_internal'],
            'single character' => ['a'],
            'digits and underscores' => ['field_123'],
            'maximum length' => [str_repeat('a', 63)],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function columnBreakoutProvider(): array
    {
        return [
            'add column' => ['x` int, ADD COLUMN `y'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidNameProvider')]
    public function testSetNameRejectsInvalidIdentifier(string $name): void
    {
        $this->expectException(\InvalidArgumentException::class);

        (new \Pimcore\Model\DataObject\ClassDefinition\Data\Input())->setName($name);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidNameProvider')]
    public function testSetValuesRejectsInvalidFieldName(string $name): void
    {
        $this->expectException(\InvalidArgumentException::class);

        (new \Pimcore\Model\DataObject\ClassDefinition\Data\Input())->setValues(['name' => $name, 'title' => 'Title']);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidNameProvider')]
    public function testClassificationstoreFieldSetNameRejectsInvalidIdentifier(string $name): void
    {
        $this->expectException(\InvalidArgumentException::class);

        (new \Pimcore\Model\DataObject\ClassDefinition\Data\Classificationstore())->setName($name);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidNameProvider')]
    public function testImportedLayoutRejectsInvalidFieldName(string $name): void
    {
        $this->expectException(\InvalidArgumentException::class);

        \Pimcore\Model\DataObject\ClassDefinition\Service::generateLayoutTreeFromArray($this->layoutWithField($name), true);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidNameProvider')]
    public function testImportedLayoutRejectsInvalidNameOfNestedLocalizedField(string $name): void
    {
        $this->expectException(\InvalidArgumentException::class);

        \Pimcore\Model\DataObject\ClassDefinition\Service::generateLayoutTreeFromArray([
            'datatype' => 'data',
            'fieldtype' => 'localizedfields',
            'name' => 'localizedfields',
            'children' => [['datatype' => 'data', 'fieldtype' => 'input', 'name' => $name, 'title' => 'Title']],
        ], true);
    }

    public function testControlClassificationstoreFieldSetNameAcceptsValidIdentifier(): void
    {
        $field = (new \Pimcore\Model\DataObject\ClassDefinition\Data\Classificationstore())->setName('attributes');

        $this->assertSame('attributes', $field->getName());
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('validNameProvider')]
    public function testControlSetNameAcceptsValidIdentifier(string $name): void
    {
        $field = (new \Pimcore\Model\DataObject\ClassDefinition\Data\Input())->setName($name);

        $this->assertSame($name, $field->getName());
    }

    public function testControlImportedLayoutKeepsValidFieldName(): void
    {
        $layout = \Pimcore\Model\DataObject\ClassDefinition\Service::generateLayoutTreeFromArray($this->layoutWithField('valid_field'), true);

        $this->assertInstanceOf(\Pimcore\Model\DataObject\ClassDefinition\Layout\Panel::class, $layout);
        $this->assertSame(['valid_field'], array_map(
            static fn (\Pimcore\Model\DataObject\ClassDefinition\Data $child): string => $child->getName(),
            $layout->getChildren(),
        ));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function classificationStoreKeyNameProvider(): array
    {
        return [
            'parentheses' => ['Weight (kg)'],
            'space' => ['Screen size'],
            'dash' => ['screen-size'],
            'leading digit' => ['1st key'],
            'umlaut' => ['Größe'],
            'long' => [str_repeat('a', 100)],
        ];
    }

    /**
     * @return array<string, array{string, \Closure(array<string, string>): \stdClass}>
     */
    public static function classificationStoreKeyStdClassProvider(): array
    {
        return [
            'stdClass input' => ['Weight (kg)', static fn (array $definition): \stdClass => (object) $definition],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('classificationStoreKeyNameProvider')]
    public function testControlClassificationStoreKeyDefinitionKeepsFreeTextName(string $name): void
    {
        $definition = \Pimcore\Model\DataObject\Classificationstore\Service::getFieldDefinitionFromJson(
            ['name' => $name, 'title' => 'Title', 'fieldtype' => 'input'],
            'input',
        );

        $this->assertInstanceOf(\Pimcore\Model\DataObject\ClassDefinition\Data\Input::class, $definition);
        $this->assertSame($name, $definition->getName());
        $this->assertSame('Title', $definition->getTitle());
    }

    /**
     * @param \Closure(array<string, string>): \stdClass $shape
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('classificationStoreKeyStdClassProvider')]
    public function testControlClassificationStoreKeyDefinitionKeepsNameForStdClassInput(string $name, \Closure $shape): void
    {
        $definition = \Pimcore\Model\DataObject\Classificationstore\Service::getFieldDefinitionFromJson(
            $shape(['name' => $name, 'title' => 'Title', 'fieldtype' => 'input']),
            'input',
        );

        $this->assertInstanceOf(\Pimcore\Model\DataObject\ClassDefinition\Data\Input::class, $definition);
        $this->assertSame($name, $definition->getName());
    }

    public function testControlClassificationStoreKeyDefinitionKeepsNameOfEncryptedDelegate(): void
    {
        $definition = \Pimcore\Model\DataObject\Classificationstore\Service::getFieldDefinitionFromJson(
            [
                'name' => 'Secret key',
                'title' => 'Title',
                'fieldtype' => 'encryptedField',
                'delegateDatatype' => 'input',
                'delegate' => ['name' => 'Secret key', 'title' => 'Title', 'fieldtype' => 'input'],
            ],
            'encryptedField',
        );

        $this->assertInstanceOf(\Pimcore\Model\DataObject\ClassDefinition\Data\EncryptedField::class, $definition);
        $this->assertSame('Secret key', $definition->getName());
        $this->assertSame('Secret key', $definition->getDelegate()?->getName());
    }

    public function testClassFieldNameWithSpaceIsRejectedNextToClassificationStoreKey(): void
    {
        \Pimcore\Model\DataObject\Classificationstore\Service::getFieldDefinitionFromJson(
            ['name' => 'Screen size', 'fieldtype' => 'input'],
            'input',
        );

        $this->expectException(\InvalidArgumentException::class);

        (new \Pimcore\Model\DataObject\ClassDefinition\Data\Input())->setName('Screen size');
    }

    public function testControlEveryDemoDefinitionLoadsWithMatchingFieldNames(): void
    {
        $names = array_map(
            static fn (string $file): string => substr(basename($file, '.php'), strlen('definition_')),
            glob(PIMCORE_CLASS_DEFINITION_DIRECTORY . '/definition_*.php') ?: [],
        );
        $this->assertCount(22, $names);

        $loaded = [];
        foreach ($names as $name) {
            $class = \Pimcore\Model\DataObject\ClassDefinition::getByName($name);
            $this->assertInstanceOf(\Pimcore\Model\DataObject\ClassDefinition::class, $class, $name);
            foreach ($class->getFieldDefinitions() as $key => $field) {
                $this->assertSame($key, $field->getName(), $name);
                $loaded[$name][] = $key;
            }
        }

        $this->assertCount(22, $loaded);
        $this->assertContains('series', $loaded['Car']);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('columnBreakoutProvider')]
    public function testAddModifyColumnKeepsBreakoutInsideOneColumnName(string $name): void
    {
        $this->db->executeStatement('CREATE TABLE `' . self::TABLE . '` (oo_id INT NOT NULL PRIMARY KEY)');

        $this->ddlDao()->addColumn(self::TABLE, $name, 'varchar(10)');

        $this->assertSame(['oo_id', $name], $this->columnNames());
    }

    public function testRemoveUnusedColumnsKeepsBreakoutInsideOneColumnName(): void
    {
        $hostile = 'q`, DROP COLUMN `keep';
        $this->db->executeStatement(
            'CREATE TABLE `' . self::TABLE . '` (oo_id INT NOT NULL PRIMARY KEY, `keep` VARCHAR(5), `q` VARCHAR(5), `' . str_replace('`', '``', $hostile) . '` VARCHAR(5))'
        );

        $this->ddlDao()->dropUnused(self::TABLE, [$hostile], ['oo_id']);

        $this->assertSame(['oo_id', 'keep', 'q'], $this->columnNames());
    }

    public function testAddIndexToFieldKeepsFieldNameInsideIdentifier(): void
    {
        $this->db->executeStatement('CREATE TABLE `' . self::TABLE . '` (oo_id INT NOT NULL PRIMARY KEY, a VARCHAR(5), `keep` VARCHAR(5))');
        $field = new \Pimcore\Model\DataObject\ClassDefinition\Data\Input();
        $field->setIndex(true);
        (new \ReflectionProperty(\Pimcore\Model\DataObject\ClassDefinition\Data::class, 'name'))->setValue($field, 'a` (`a`), DROP COLUMN `keep` -- ');

        $this->ddlDao()->indexField($field, self::TABLE);

        $this->assertSame(['oo_id', 'a', 'keep'], $this->columnNames());
    }

    public function testControlAddModifyColumnCreatesRegularColumn(): void
    {
        $this->db->executeStatement('CREATE TABLE `' . self::TABLE . '` (oo_id INT NOT NULL PRIMARY KEY)');

        $this->ddlDao()->addColumn(self::TABLE, 'my_field_1', 'varchar(10)');

        $this->assertSame(['oo_id', 'my_field_1'], $this->columnNames());
    }

    public function testControlAddIndexToFieldCreatesRegularIndex(): void
    {
        $this->db->executeStatement('CREATE TABLE `' . self::TABLE . '` (oo_id INT NOT NULL PRIMARY KEY, a VARCHAR(5))');
        $field = (new \Pimcore\Model\DataObject\ClassDefinition\Data\Input())->setName('a');
        $field->setIndex(true);

        $this->ddlDao()->indexField($field, self::TABLE);

        $this->assertSame(
            ['a'],
            array_map(
                static fn (array $row): string => (string) $row['Column_name'],
                $this->db->fetchAllAssociative('SHOW INDEXES FROM `' . self::TABLE . '` WHERE Key_name = ?', ['p_index_a']),
            ),
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function layoutWithField(string $name): array
    {
        return [
            'datatype' => 'layout',
            'fieldtype' => 'panel',
            'name' => 'Layout',
            'children' => [
                [
                    'datatype' => 'data',
                    'fieldtype' => 'input',
                    'name' => $name,
                    'title' => 'Title',
                ],
            ],
        ];
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

    private function ddlDao(): object
    {
        $dao = new class() extends \Pimcore\Model\DataObject\ClassDefinition\Dao {
            public function __construct()
            {
                $this->db = \Pimcore\Db::get();
            }

            public function addColumn(string $table, string $column, string $type): void
            {
                $this->addModifyColumn($table, $column, $type, '', 'NULL');
            }

            /**
             * @param list<string> $columns
             * @param list<string> $protected
             */
            public function dropUnused(string $table, array $columns, array $protected): void
            {
                $this->removeUnusedColumns($table, $columns, $protected);
            }

            public function indexField(\Pimcore\Model\DataObject\ClassDefinition\Data $field, string $table): void
            {
                $this->addIndexToField($field, $table, 'getQueryColumnType');
            }
        };

        return $dao;
    }
}
