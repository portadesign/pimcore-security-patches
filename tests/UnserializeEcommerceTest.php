<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-45162')]
final class UnserializeEcommerceTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var list<\Closure>
     */
    private array $cleanups = [];

    protected function setUp(): void
    {
        $this->resetCanary();
    }

    protected function tearDown(): void
    {
        foreach (array_reverse($this->cleanups) as $cleanup) {
            $cleanup();
        }
        $this->cleanups = [];
        $this->resetCanary();
    }

    /**
     * @return array<string, array{string}>
     */
    public static function ruleObjectKeyProvider(): array
    {
        return [
            'condition' => ['condition'],
            'actions' => ['actions'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('ruleObjectKeyProvider')]
    public function testPricingRuleLeavesRuleUnchangedForTopLevelForeignObject(string $key): void
    {
        $rule = new \Pimcore\Bundle\EcommerceFrameworkBundle\PricingManager\Rule();

        $rule->setValue($key, $this->serialized(fn (): mixed => $this->canary()));

        $this->assertSame(
            ['canaryExecutions' => 0, 'condition' => null, 'actions' => []],
            ['canaryExecutions' => $this->canaryExecutions(), 'condition' => $rule->getCondition(), 'actions' => $rule->getActions()],
        );
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('ruleObjectKeyProvider')]
    public function testPricingRuleDoesNotInstantiateForeignObjectNestedInList(string $key): void
    {
        $rule = new \Pimcore\Bundle\EcommerceFrameworkBundle\PricingManager\Rule();

        $rule->setValue($key, $this->serialized(fn (): mixed => [$this->canary()]));

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in PricingManager\\Rule::setValue().');
        $this->assertSame([null, []], [$rule->getCondition(), $rule->getActions()]);
    }

    public function testPricingRuleDoesNotInstantiateForeignObjectNestedInBracket(): void
    {
        $rule = new \Pimcore\Bundle\EcommerceFrameworkBundle\PricingManager\Rule();
        $bracket = new \Pimcore\Bundle\EcommerceFrameworkBundle\PricingManager\Condition\Bracket();
        $conditions = new \ReflectionProperty($bracket, 'conditions');
        $conditions->setValue($bracket, [$this->canary()]);

        $rule->setValue('condition', $this->serialized(fn (): mixed => $bracket));

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in PricingManager\\Rule::setValue().');
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('localizedRuleKeyProvider')]
    public function testPricingRuleLocalizedValueDoesNotInstantiateForeignObject(string $key): void
    {
        $rule = new \Pimcore\Bundle\EcommerceFrameworkBundle\PricingManager\Rule();

        $rule->setValue($key, $this->serialized(fn (): mixed => ['en' => $this->canary()]));

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in PricingManager\\Rule::setValue().');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function localizedRuleKeyProvider(): array
    {
        return [
            'label' => ['label'],
            'description' => ['description'],
        ];
    }

    public function testControlPricingRuleRestoresBracketWithDateRangeAndProjectCondition(): void
    {
        $bracket = new \Pimcore\Bundle\EcommerceFrameworkBundle\PricingManager\Condition\Bracket();
        $amount = new \Pimcore\Bundle\EcommerceFrameworkBundle\PricingManager\Condition\CartAmount();
        $amount->setLimit(100);
        $range = new \Pimcore\Bundle\EcommerceFrameworkBundle\PricingManager\Condition\DateRange();
        $range->setStarting(new \DateTime('2024-01-01 10:00:00'));
        $range->setEnding(new \DateTime('2024-02-01 10:00:00'));
        $project = new \Portadesign\PimcoreSecurityPatches\Tests\Support\P2ProjectCondition();
        $project->setLimit(7);
        $bracket->addCondition($amount, \Pimcore\Bundle\EcommerceFrameworkBundle\PricingManager\Condition\BracketInterface::OPERATOR_AND);
        $bracket->addCondition($range, \Pimcore\Bundle\EcommerceFrameworkBundle\PricingManager\Condition\BracketInterface::OPERATOR_AND);
        $bracket->addCondition($project, \Pimcore\Bundle\EcommerceFrameworkBundle\PricingManager\Condition\BracketInterface::OPERATOR_AND);
        $rule = new \Pimcore\Bundle\EcommerceFrameworkBundle\PricingManager\Rule();

        $rule->setValue('condition', serialize($bracket));

        $this->assertEquals($bracket, $rule->getCondition());
        $restored = $rule->getCondition()->getConditionsByType(\Portadesign\PimcoreSecurityPatches\Tests\Support\P2ProjectCondition::class);
        $this->assertCount(1, $restored);
        $this->assertSame(
            ['2024-01-01 10:00:00', '2024-02-01 10:00:00'],
            [
                $rule->getCondition()->getConditionsByType(\Pimcore\Bundle\EcommerceFrameworkBundle\PricingManager\Condition\DateRange::class)[0]->getStarting()->format('Y-m-d H:i:s'),
                $rule->getCondition()->getConditionsByType(\Pimcore\Bundle\EcommerceFrameworkBundle\PricingManager\Condition\DateRange::class)[0]->getEnding()->format('Y-m-d H:i:s'),
            ],
        );
    }

    public function testControlPricingRuleRestoresActions(): void
    {
        $discount = new \Pimcore\Bundle\EcommerceFrameworkBundle\PricingManager\Action\CartDiscount();
        $discount->setAmount(5);
        $rule = new \Pimcore\Bundle\EcommerceFrameworkBundle\PricingManager\Rule();

        $rule->setValue('actions', serialize([$discount]));

        $this->assertEquals([$discount], $rule->getActions());
    }

    public function testControlPricingRuleRestoresLocalizedLabel(): void
    {
        $rule = new \Pimcore\Bundle\EcommerceFrameworkBundle\PricingManager\Rule();

        $rule->setValue('label', serialize(['en' => 'Summer sale', 'cs' => 'Letní výprodej']));

        $this->assertSame(['Summer sale', 'Letní výprodej'], [$rule->getLabel('en'), $rule->getLabel('cs')]);
    }

    public function testSessionCartsSkipForeignObjectAndKeepLegitimateCart(): void
    {
        $this->useCartSession();
        $cart = new \Pimcore\Bundle\EcommerceFrameworkBundle\CartManager\SessionCart();
        $cart->setId('sesscart_pd_sec_legit');
        $bag = $this->cartBag();
        $bag->set('carts', [
            'foreign' => $this->serialized(fn (): mixed => $this->canary()),
            'sesscart_pd_sec_legit' => serialize($cart),
        ]);
        $this->resetCanary();

        $carts = \Pimcore\Bundle\EcommerceFrameworkBundle\CartManager\SessionCart::getAllCartsForUser(-1);

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in SessionCart::getAllCartsForUser().');
        $this->assertSame(['sesscart_pd_sec_legit'], array_keys($carts));
    }

    public function testControlSessionCartsRestoreProjectCartSubclass(): void
    {
        $this->useCartSession();
        $cart = new \Portadesign\PimcoreSecurityPatches\Tests\Support\P2ProjectCart();
        $cart->setId('sesscart_pd_sec_project');
        $this->cartBag()->set('carts', ['sesscart_pd_sec_project' => serialize($cart)]);

        $carts = \Pimcore\Bundle\EcommerceFrameworkBundle\CartManager\SessionCart::getAllCartsForUser(-1);

        $this->assertSame(['sesscart_pd_sec_project'], array_keys($carts));
        $this->assertInstanceOf(\Portadesign\PimcoreSecurityPatches\Tests\Support\P2ProjectCart::class, $carts['sesscart_pd_sec_project']);
    }

    /**
     * @return array<string, array{class-string}>
     */
    public static function indexQueueCommandProvider(): array
    {
        return [
            'update queue' => [\Pimcore\Bundle\EcommerceFrameworkBundle\Command\IndexService\ProcessUpdateIndexQueueCommand::class],
            'preparation queue' => [\Pimcore\Bundle\EcommerceFrameworkBundle\Command\IndexService\ProcessPreparationQueueCommand::class],
        ];
    }

    /**
     * @param class-string $class
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('indexQueueCommandProvider')]
    public function testIndexQueueRowNeverInstantiatesForeignObject(string $class): void
    {
        $command = $this->queueCommand($class);

        try {
            $this->runQueueRow($command, $this->serialized(fn (): mixed => ['id' => 1, 'tenants' => [], 'gadget' => $this->canary()]));
        } catch (\Throwable) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in ' . $class . '::runSingleCommand().');
    }

    /**
     * @param class-string $class
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('indexQueueCommandProvider')]
    public function testIndexQueueRowAsTopLevelForeignObjectIsNotInstantiated(string $class): void
    {
        $command = $this->queueCommand($class);

        try {
            $this->runQueueRow($command, $this->serialized(fn (): mixed => $this->canary()));
        } catch (\Throwable) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in ' . $class . '::runSingleCommand().');
    }

    /**
     * @param class-string $class
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('indexQueueCommandProvider')]
    public function testControlIndexQueueRowIsProcessed(string $class): void
    {
        $command = $this->queueCommand($class, 1);

        $this->runQueueRow($command, serialize(['id' => 1, 'tenants' => []]));
    }

    public function testMockupCacheItemNeverInstantiatesForeignObject(): void
    {
        $worker = $this->mockupWorker();
        $this->cacheMockup($worker, 4711, $this->serialized(fn (): mixed => $this->canary()));

        try {
            $worker->getMockupFromCache(4711);
        } catch (\Throwable) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in getMockupFromCache().');
    }

    public function testMockupCacheItemNeverInstantiatesForeignObjectNestedInMockup(): void
    {
        $worker = $this->mockupWorker();
        $mockup = new \Pimcore\Bundle\EcommerceFrameworkBundle\Model\DefaultMockup(1, ['k' => $this->canary()], []);
        $this->cacheMockup($worker, 4712, $this->serialized(fn (): mixed => $mockup));

        try {
            $worker->getMockupFromCache(4712);
        } catch (\Throwable) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in getMockupFromCache().');
    }

    /**
     * @return array<string, array{class-string<\Pimcore\Bundle\EcommerceFrameworkBundle\Model\DefaultMockup>}>
     */
    public static function mockupClassProvider(): array
    {
        return [
            'default mockup' => [\Pimcore\Bundle\EcommerceFrameworkBundle\Model\DefaultMockup::class],
            'project mockup subclass' => [\Portadesign\PimcoreSecurityPatches\Tests\Support\P2ProjectMockup::class],
        ];
    }

    /**
     * @param class-string<\Pimcore\Bundle\EcommerceFrameworkBundle\Model\DefaultMockup> $class
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('mockupClassProvider')]
    public function testControlMockupCacheReturnsSerializedMockup(string $class): void
    {
        $worker = $this->mockupWorker();
        $this->cacheMockup($worker, 4713, serialize(new $class(4713, ['name' => 'pd-sec'], [])));

        $mockup = $worker->getMockupFromCache(4713);

        $this->assertInstanceOf($class, $mockup);
        $this->assertSame([4713, ['name' => 'pd-sec']], [$mockup->getId(), $mockup->getParams()]);
    }

    private function useCartSession(): void
    {
        $session = new \Symfony\Component\HttpFoundation\Session\Session(new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage());
        $bag = new \Symfony\Component\HttpFoundation\Session\Attribute\AttributeBag('_pd_sec_cart');
        $bag->setName(\Pimcore\Bundle\EcommerceFrameworkBundle\EventListener\SessionBagListener::ATTRIBUTE_BAG_CART);
        $session->registerBag($bag);
        $request = new \Symfony\Component\HttpFoundation\Request();
        $request->setSession($session);
        $stack = \Pimcore::getContainer()->get('request_stack');
        $stack->push($request);
        $property = new \ReflectionProperty(\Pimcore\Bundle\EcommerceFrameworkBundle\CartManager\SessionCart::class, 'unserializedCarts');
        $property->setValue(null, null);
        $this->cleanups[] = static function () use ($stack, $property): void {
            $stack->pop();
            $property->setValue(null, null);
        };
    }

    private function cartBag(): \Symfony\Component\HttpFoundation\Session\Attribute\AttributeBagInterface
    {
        return \Pimcore::getContainer()->get('request_stack')->getSession()->getBag(\Pimcore\Bundle\EcommerceFrameworkBundle\EventListener\SessionBagListener::ATTRIBUTE_BAG_CART);
    }

    /**
     * @param class-string $class
     */
    private function queueCommand(string $class, ?int $expectedTenantLookups = null): object
    {
        $command = (new \ReflectionClass($class))->newInstanceWithoutConstructor();
        $indexService = $this->createMock(\Pimcore\Bundle\EcommerceFrameworkBundle\IndexService\IndexService::class);
        $indexService->expects(null === $expectedTenantLookups ? $this->any() : $this->exactly($expectedTenantLookups))->method('getTenants')->willReturn([]);
        (new \ReflectionProperty($command, 'indexService'))->setValue($command, $indexService);

        return $command;
    }

    private function runQueueRow(object $command, string $serializedRow): void
    {
        $this->resetCanary();
        (new \ReflectionMethod($command, 'runSingleCommand'))->invoke(
            $command,
            $serializedRow,
            new \Symfony\Component\Console\Input\ArrayInput([]),
            new \Symfony\Component\Console\Output\BufferedOutput(),
        );
    }

    private function mockupWorker(): \Pimcore\Bundle\EcommerceFrameworkBundle\IndexService\Worker\OptimizedMysql
    {
        $worker = (new \ReflectionClass(\Pimcore\Bundle\EcommerceFrameworkBundle\IndexService\Worker\OptimizedMysql::class))->newInstanceWithoutConstructor();
        (new \ReflectionProperty($worker, 'name'))->setValue($worker, 'pd-sec-tenant');
        (new \ReflectionProperty($worker, 'mySqlHelper'))->setValue($worker, $this->createStub(\Pimcore\Bundle\EcommerceFrameworkBundle\IndexService\Worker\Helper\MySql::class));

        return $worker;
    }

    private function cacheMockup(object $worker, int $objectId, string $serialized): void
    {
        $key = (new \ReflectionMethod($worker, 'createMockupCacheKey'))->invoke($worker, $objectId);
        \Pimcore\Cache::save($serialized, $key, [], null, 0, true);
        $this->cleanups[] = static function () use ($key): void {
            \Pimcore\Cache::remove($key);
        };
        $this->resetCanary();
    }

    private function canary(): object
    {
        return new \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary();
    }

    private function serialized(\Closure $factory): string
    {
        return \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::serialized($factory);
    }

    private function resetCanary(): void
    {
        gc_collect_cycles();
        \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::reset();
    }

    private function canaryExecutions(): int
    {
        return \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::$executions;
    }
}
