<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-55072')]
final class ClassDefinitionIdentifierTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;

    private const PROBE_NAME = 'PdSecP2Probe';

    private const PROBE_ADMIN = 'pd-sec-class-identifier-admin';

    private ?\Closure $persistenceSentinel = null;

    protected function tearDown(): void
    {
        if ($this->persistenceSentinel instanceof \Closure) {
            $dispatcher = \Pimcore::getEventDispatcher();
            $dispatcher->removeListener(\Pimcore\Event\DataObjectClassDefinitionEvents::PRE_ADD, $this->persistenceSentinel);
            $dispatcher->removeListener(\Pimcore\Event\DataObjectClassDefinitionEvents::PRE_UPDATE, $this->persistenceSentinel);
            $this->persistenceSentinel = null;
        }

        $this->authenticate(null);
        $this->deleteUserByName(self::PROBE_ADMIN);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidIdProvider(): array
    {
        return [
            'embedded newline' => ["valid\nmalicious"],
            'trailing newline' => ["valid\n"],
            'sql payload from advisory' => ['1 UNION SELECT password FROM users-- '],
            'space' => ['a b'],
            'semicolon' => ['a;b'],
            'dash' => ['a-b'],
            'backtick' => ['a`b'],
            'double quote' => ['a"b'],
            'single quote' => ["a'b"],
            'property breakout' => ['PdSec"; public $pdInjected = "b'],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidNameProvider(): array
    {
        return [
            'embedded newline' => ["Valid\nName"],
            'trailing newline' => ["ValidName\n"],
            'space' => ['Bad Name'],
            'semicolon' => ['Bad;Name'],
            'leading digit' => ['1Name'],
            'dash' => ['Bad-Name'],
            'single quote' => ["Bad'Name"],
            'class body breakout' => ['Foo{}x'],
            'path traversal' => ['../../xx'],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function existingClassProvider(): array
    {
        $cases = [];

        foreach (glob(PIMCORE_CLASS_DEFINITION_DIRECTORY . '/definition_*.php') ?: [] as $file) {
            $name = substr(basename($file, '.php'), strlen('definition_'));
            $cases[$name] = [$name];
        }

        return $cases;
    }

    /**
     * @return array<string, array{string, string, string}>
     */
    public static function hostileBuilderInputProvider(): array
    {
        $cases = [];
        $inputs = [
            'id breaks out of string' => ['a";}public function pd(){}//', 'Valid'],
            'name closes class body' => ['A1', 'Foo{}x'],
            'name is a path' => ['A1', '../../xx'],
        ];
        foreach (['class builder', 'listing builder', 'properties builder'] as $builder) {
            foreach ($inputs as $label => [$id, $name]) {
                $cases[$builder . ': ' . $label] = [$builder, $id, $name];
            }
        }

        return $cases;
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidIdProvider')]
    public function testSaveRejectsInvalidId(string $id): void
    {
        $this->installPersistenceSentinel();
        $class = $this->newClass(id: $id, name: 'ValidName');

        $this->expectExceptionObject(new \Exception(sprintf('Invalid ID `%s` for class definition ValidName', $id)));

        $class->save(false);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidNameProvider')]
    public function testSaveRejectsInvalidName(string $name): void
    {
        $this->installPersistenceSentinel();
        $class = $this->newClass(id: 'ValidId1', name: $name);

        $this->expectExceptionObject(new \Exception(sprintf('Invalid name for class definition: %s', $name)));

        $class->save(false);
    }

    public function testControlSaveAcceptsValidIdAndName(): void
    {
        $this->installPersistenceSentinel();
        $class = $this->newClass(id: 'ValidId_1', name: 'ValidName_1');

        $this->expectExceptionObject(new \RuntimeException('persistence reached'));

        $class->save(false);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('existingClassProvider')]
    public function testControlExistingHostClassPassesValidation(string $name): void
    {
        $this->installPersistenceSentinel();
        $class = \Pimcore\Model\DataObject\ClassDefinition::getByName($name);
        $this->assertInstanceOf(\Pimcore\Model\DataObject\ClassDefinition::class, $class);

        $this->expectExceptionObject(new \RuntimeException('persistence reached'));

        $class->save(false);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('hostileBuilderInputProvider')]
    public function testGeneratedPhpNeverEmbedsHostileIdOrName(string $builder, string $id, string $name): void
    {
        $class = $this->newClass(id: $id, name: $name);
        $thrown = null;
        $code = '';

        try {
            $code = $this->build($builder, $class);
        } catch (\InvalidArgumentException $e) {
            $thrown = $e;
        }

        $this->assertSame(
            [true, ''],
            [$thrown instanceof \InvalidArgumentException, $this->lineContaining($code, [$id, $name])],
            'The ' . $builder . ' emitted PHP source containing the hostile id or name.',
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function builderProvider(): array
    {
        return [
            'class builder' => ['class builder'],
            'listing builder' => ['listing builder'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('builderProvider')]
    public function testControlBuildersReproduceGeneratedFilesOfEveryHostClassByteForByte(string $builder): void
    {
        $names = array_map(
            static fn (string $file): string => substr(basename($file, '.php'), strlen('definition_')),
            glob(PIMCORE_CLASS_DEFINITION_DIRECTORY . '/definition_*.php') ?: [],
        );
        $this->assertCount(22, $names);

        $mismatches = [];
        foreach ($names as $name) {
            $class = \Pimcore\Model\DataObject\ClassDefinition::getByName($name);
            $this->assertInstanceOf(\Pimcore\Model\DataObject\ClassDefinition::class, $class);
            $file = 'class builder' === $builder ? $class->getPhpClassFile() : $class->getPhpListingClassFile();
            if ($this->build($builder, $class) !== file_get_contents($file)) {
                $mismatches[] = $name;
            }
        }

        $this->assertSame([], $mismatches);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function validIdentifierProvider(): array
    {
        return [
            'short upper-case id' => ['AP', 'AccessoryPart'],
            'id with underscore' => ['EF_FD', 'FilterDefinition'],
            'numeric id' => ['5', 'LinkActivityDefinition'],
            'lower-case name with digits and underscore' => ['x1_y', 'valid_1'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('validIdentifierProvider')]
    public function testControlBuilderWritesValidIdAndNameVerbatimIntoParsablePhp(string $id, string $name): void
    {
        $class = $this->newClass(id: $id, name: $name);

        foreach (['class builder', 'listing builder'] as $builder) {
            $code = $this->build($builder, $class);

            $this->assertNotEmpty(token_get_all($code, TOKEN_PARSE), $builder);
            $this->assertStringContainsString(
                'class builder' === $builder ? 'protected $o_classId = "' . $id . '";' : 'protected $classId = "' . $id . '";',
                $code,
                $builder,
            );
            $this->assertStringContainsString('"' . $name . '";', $code, $builder);
        }
    }

    public function testAddActionRejectsClassIdentifierThatBreaksOutOfGeneratedPhp(): void
    {
        $this->authenticate(\Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::PROBE_ADMIN,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => false,
            'admin' => true,
        ]));
        $identifier = 'PdSec"; public $pdInjected = "b';
        $controller = \Pimcore::getContainer()->get(\Pimcore\Bundle\AdminBundle\Controller\Admin\DataObject\ClassController::class);

        try {
            $thrown = false;
            try {
                $controller->addAction(new \Symfony\Component\HttpFoundation\Request([], [
                    'className' => self::PROBE_NAME,
                    'classIdentifier' => $identifier,
                ]));
            } catch (\Throwable) {
                $thrown = true;
            }

            $this->assertSame(
                ['thrown' => true, 'classRows' => [], 'files' => [], 'filesContainingPayload' => []],
                [
                    'thrown' => $thrown,
                    'classRows' => \Pimcore\Db::get()->fetchAllAssociative('SELECT id, name FROM classes WHERE name = ?', [self::PROBE_NAME]),
                    'files' => $this->probeFiles(),
                    'filesContainingPayload' => array_values(array_filter(
                        $this->probeFiles(),
                        static fn (string $file): bool => is_file($file) && str_contains((string) file_get_contents($file), 'pdInjected'),
                    )),
                ],
            );
        } finally {
            $this->removeProbeClass($identifier);
        }

        $this->assertSame([], $this->probeResidue());
    }

    public function testBlockLoadQuotesClassIdInTableName(): void
    {
        $realClassId = \Pimcore\Db::get()->fetchOne('SELECT id FROM classes ORDER BY CHAR_LENGTH(id), id LIMIT 1');
        $this->assertNotFalse($realClassId, 'The host needs at least one class definition.');

        $object = new \Pimcore\Model\DataObject\Concrete();
        $object->setId(1);
        $object->setClassId($realClassId . " UNION SELECT 'a:0:{}'#");

        $block = new \Pimcore\Model\DataObject\ClassDefinition\Data\Block();
        $block->setName('oo_id');

        $this->expectException(\Doctrine\DBAL\Exception\TableNotFoundException::class);

        $block->load($object);
    }

    /**
     * @return array<string, array{\Closure(\Pimcore\Model\DataObject\Concrete): array{object: object, params: array<string, mixed>}}>
     */
    public static function blockLoadBranchProvider(): array
    {
        return [
            'object brick store' => [static fn (\Pimcore\Model\DataObject\Concrete $owner): array => [
                'object' => new class($owner) extends \Pimcore\Model\DataObject\Objectbrick\Data\AbstractData {
                },
                'params' => ['context' => ['object' => $owner, 'containerKey' => 'B', 'brickField' => 'f', 'fieldname' => 'bricks']],
            ]],
            'field collection store' => [static fn (\Pimcore\Model\DataObject\Concrete $owner): array => [
                'object' => new class() extends \Pimcore\Model\DataObject\Fieldcollection\Data\AbstractData {
                },
                'params' => ['context' => ['object' => $owner, 'containerKey' => 'C', 'fieldname' => 'collection', 'index' => 0]],
            ]],
            'localized data' => [static fn (\Pimcore\Model\DataObject\Concrete $owner): array => [
                'object' => new \Pimcore\Model\DataObject\Localizedfield(),
                'params' => ['language' => 'en', 'context' => ['object' => $owner]],
            ]],
            'localized data of field collection' => [static fn (\Pimcore\Model\DataObject\Concrete $owner): array => [
                'object' => new \Pimcore\Model\DataObject\Localizedfield(),
                'params' => ['language' => 'en', 'context' => ['object' => $owner, 'containerType' => 'fieldcollection', 'containerKey' => 'C', 'fieldname' => 'collection', 'index' => 0]],
            ]],
            'localized data of object brick' => [static fn (\Pimcore\Model\DataObject\Concrete $owner): array => [
                'object' => new \Pimcore\Model\DataObject\Localizedfield(),
                'params' => ['language' => 'en', 'context' => ['object' => $owner, 'containerType' => 'objectbrick', 'containerKey' => 'B', 'fieldname' => 'bricks']],
            ]],
        ];
    }

    /**
     * @param \Closure(\Pimcore\Model\DataObject\Concrete): array{object: \Pimcore\Model\DataObject\Localizedfield|\Pimcore\Model\DataObject\Objectbrick\Data\AbstractData|\Pimcore\Model\DataObject\Fieldcollection\Data\AbstractData, params: array<string, mixed>} $branch
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('blockLoadBranchProvider')]
    public function testBlockLoadQuotesClassIdInTableNameOfEveryContainer(\Closure $branch): void
    {
        $owner = new \Pimcore\Model\DataObject\Concrete();
        $owner->setId(1);
        $owner->setClassId('x UNION SELECT 1#');
        ['object' => $object, 'params' => $params] = $branch($owner);

        $block = new \Pimcore\Model\DataObject\ClassDefinition\Data\Block();
        $block->setName('f');

        try {
            $block->load($object, $params);
            $this->fail('The query for a non-existing table did not fail.');
        } catch (\Doctrine\DBAL\Exception\TableNotFoundException $e) {
            $this->assertStringContainsString('x UNION SELECT 1#', $e->getPrevious()?->getMessage() ?? '');
        }
    }

    private function installPersistenceSentinel(): void
    {
        $this->persistenceSentinel = static function (): never {
            throw new \RuntimeException('persistence reached');
        };

        $dispatcher = \Pimcore::getEventDispatcher();
        $dispatcher->addListener(\Pimcore\Event\DataObjectClassDefinitionEvents::PRE_ADD, $this->persistenceSentinel);
        $dispatcher->addListener(\Pimcore\Event\DataObjectClassDefinitionEvents::PRE_UPDATE, $this->persistenceSentinel);
    }

    private function newClass(string $id, string $name): \Pimcore\Model\DataObject\ClassDefinition
    {
        $class = new \Pimcore\Model\DataObject\ClassDefinition();
        $class->setId($id);
        $class->setName($name);

        return $class;
    }

    private function build(string $builder, \Pimcore\Model\DataObject\ClassDefinition $class): string
    {
        $properties = new \Pimcore\DataObject\ClassBuilder\FieldDefinitionPropertiesBuilder();

        return match ($builder) {
            'class builder' => (new \Pimcore\DataObject\ClassBuilder\ClassBuilder(
                new \Pimcore\DataObject\ClassBuilder\FieldDefinitionDocBlockBuilder(),
                $properties,
                new \Pimcore\DataObject\ClassBuilder\FieldDefinitionBuilder(),
            ))->buildClass($class),
            'listing builder' => (new \Pimcore\DataObject\ClassBuilder\ListingClassBuilder(
                new \Pimcore\DataObject\ClassBuilder\ListingClassFieldDefinitionBuilder(),
            ))->buildListingClass($class),
            'properties builder' => $properties->buildProperties($class),
        };
    }

    /**
     * @param list<string> $needles
     */
    private function lineContaining(string $code, array $needles): string
    {
        foreach (explode("\n", $code) as $line) {
            foreach ($needles as $needle) {
                if (strlen($needle) > 3 && str_contains($line, $needle)) {
                    return $line;
                }
            }
        }

        return '';
    }

    /**
     * @return list<string>
     */
    private function probeFiles(): array
    {
        return array_values(array_filter([
            PIMCORE_CLASS_DEFINITION_DIRECTORY . '/definition_' . self::PROBE_NAME . '.php',
            PIMCORE_CLASS_DIRECTORY . '/DataObject/' . self::PROBE_NAME . '.php',
            PIMCORE_CLASS_DIRECTORY . '/DataObject/' . self::PROBE_NAME . '/Listing.php',
            PIMCORE_CLASS_DIRECTORY . '/DataObject/' . self::PROBE_NAME,
        ], 'file_exists'));
    }

    /**
     * @return list<string>
     */
    private function probeResidue(): array
    {
        $db = \Pimcore\Db::get();

        return array_values(array_merge(
            $this->probeFiles(),
            array_map(static fn (string $id): string => 'classes row ' . $id, $db->fetchFirstColumn('SELECT id FROM classes WHERE name = ?', [self::PROBE_NAME])),
            array_map(static fn (string $table): string => 'table ' . $table, $db->fetchFirstColumn("SHOW TABLES LIKE '%PdSec%'")),
        ));
    }

    private function removeProbeClass(string $identifier): void
    {
        $class = \Pimcore\Model\DataObject\ClassDefinition::getByName(self::PROBE_NAME);
        if (!$class instanceof \Pimcore\Model\DataObject\ClassDefinition) {
            $class = $this->newClass(id: $identifier, name: self::PROBE_NAME);
        }

        try {
            $class->delete();
        } catch (\Throwable) {
        }

        foreach ($this->probeFiles() as $path) {
            if (is_file($path)) {
                unlink($path);
            }
        }
        if (is_dir(PIMCORE_CLASS_DIRECTORY . '/DataObject/' . self::PROBE_NAME)) {
            rmdir(PIMCORE_CLASS_DIRECTORY . '/DataObject/' . self::PROBE_NAME);
        }
    }
}
