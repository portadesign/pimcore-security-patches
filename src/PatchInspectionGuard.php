<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches;

final class PatchInspectionGuard
{
    /**
     * @param array{checked: int, missing: array<string, int>} $inspection
     *
     * @throws \RuntimeException when patches are still missing, or when patches are expected and none could be verified
     */
    public function assertApplied(array $inspection, bool $patchesExpected, string $output): void
    {
        if ([] !== $inspection['missing']) {
            $missing = [];
            foreach ($inspection['missing'] as $package => $count) {
                $missing[] = sprintf('%d in %s', $count, $package);
            }

            throw new \RuntimeException(sprintf(
                "Patches still missing after re-applying (%s). Output of the patches commands:\n%s",
                implode(separator: ', ', array: $missing),
                $output,
            ));
        }

        if ($patchesExpected && 0 === $inspection['checked']) {
            throw new \RuntimeException(sprintf(
                "No patch could be verified after re-applying (neither patch nor git available, or patch files not retrievable). Output of the patches commands:\n%s",
                $output,
            ));
        }
    }
}
