"""Require fixed repository target flags and explicit diagnostic scalar builds."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('composition_build',
    Path(__file__).parents[1] / 'bench/build-composition-intra.py')
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)
CONFIG = {'target': {'cfg(target_arch = "x86_64")': {'rustflags': BUILD.V3_FLAGS}}}


class CompositionBuildTests(unittest.TestCase):
    def test_v3_configuration_comes_from_repository_without_environment_override(self):
        result = BUILD.controlled_configuration({}, machine='x86_64', config=CONFIG)
        self.assertEqual(result['effective_rustflags'], '-C target-cpu=x86-64-v3')
        self.assertFalse(result['diagnostic_only'])
        for flags in ('-C target-cpu=native', '-C target-feature=+avx2',
                      '-C target-cpu=x86-64-v3', BUILD.SCALAR_FLAGS):
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                BUILD.controlled_configuration({'RUSTFLAGS': flags}, machine='x86_64', config=CONFIG)

    def test_only_explicit_scalar_diagnostic_can_override_target_baseline(self):
        result = BUILD.controlled_configuration({'RUSTFLAGS': BUILD.SCALAR_FLAGS},
            diagnostic_scalar=True, machine='x86_64', config=CONFIG)
        self.assertTrue(result['diagnostic_only'])
        self.assertEqual(result['effective_rustflags'], BUILD.SCALAR_FLAGS)
        for environment, machine in (({}, 'x86_64'),
                ({'RUSTFLAGS': '-C target-cpu=native'}, 'x86_64'),
                ({'RUSTFLAGS': BUILD.SCALAR_FLAGS}, 'aarch64')):
            with self.subTest(environment=environment, machine=machine), self.assertRaises(ValueError):
                BUILD.controlled_configuration(environment, diagnostic_scalar=True,
                    machine=machine, config=CONFIG)

    def test_encoded_target_wrapper_and_release_profile_overrides_are_rejected(self):
        for name in ('CARGO_ENCODED_RUSTFLAGS', 'RUSTC', 'RUSTC_BOOTSTRAP',
                     'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_RUSTFLAGS',
                     'CARGO_BUILD_TARGET', 'CARGO_BUILD_RUSTC', 'CARGO_BUILD_RUSTC_WRAPPER',
                     'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER',
                     'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS',
                     'CARGO_PROFILE_RELEASE_LTO', 'CARGO_PROFILE_RELEASE_CODEGEN_UNITS'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                BUILD.controlled_configuration({name: 'override'}, machine='x86_64', config=CONFIG)
        with self.assertRaises(ValueError):
            BUILD.controlled_configuration({}, machine='x86_64', config={})

    def test_commands_execute_from_repository_root_to_load_target_configuration(self):
        with patch.object(BUILD.subprocess, 'run') as run:
            BUILD.command('cargo', 'build', '--release')
        run.assert_called_once_with(('cargo', 'build', '--release'), check=True, cwd=BUILD.ROOT)


if __name__ == '__main__':
    unittest.main()
