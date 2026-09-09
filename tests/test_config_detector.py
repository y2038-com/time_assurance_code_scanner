#!/usr/bin/env python3
"""Basic tests for config_detector Phase 1 functionality."""

import sys
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config_detector.detector import ConfigDetector
from config_detector.build_parsers import MakefileParser, CMakeParser
from config_detector.analyzers import ArchitectureDetector, TimeTConfigDetector


def test_makefile_parser():
    """Test Makefile parser."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        
        # Create a test Makefile
        makefile = tmp_path / "Makefile"
        makefile.write_text("""
CC = arm-none-eabi-gcc
CFLAGS = -m32 -D_TIME_BITS=64 -Os
ARCH = arm
""")
        
        parser = MakefileParser(tmp_path)
        result = parser.extract_all()
        
        assert result['build_files_found'] == 1
        assert '-m32' in result['cflags']
        assert 'TIME_BITS=64' in result['defines'] or any('TIME_BITS' in d for d in result['defines'])
        assert result['toolchain'] == 'arm-none-eabi'
        print("✓ Makefile parser test passed")


def test_cmake_parser():
    """Test CMake parser."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        
        # Create a test CMakeLists.txt
        cmake_file = tmp_path / "CMakeLists.txt"
        cmake_file.write_text("""
set(CMAKE_SYSTEM_PROCESSOR "arm")
set(CMAKE_C_FLAGS "-m32 -D_TIME_BITS=64")
add_definitions(-DFOO -DBAR=value)
""")
        
        parser = CMakeParser(tmp_path)
        result = parser.extract_all()
        
        assert result['build_files_found'] == 1
        assert result['variables']['CMAKE_SYSTEM_PROCESSOR'] == 'arm'
        assert '-m32' in result['cflags']
        print("✓ CMake parser test passed")


def test_architecture_detector():
    """Test architecture detection."""
    detector = ArchitectureDetector()
    
    # Test with -m32 flag
    extracted = {
        'cflags': ['-m32', '-Os'],
        'defines': [],
        'variables': {},
        'toolchain': ''
    }
    arch, conf, evidence = detector.detect(extracted)
    assert arch == 'ILP32'
    assert conf > 0.9
    print("✓ Architecture detector test passed (ILP32)")
    
    # Test with -m64 flag
    extracted = {
        'cflags': ['-m64'],
        'defines': [],
        'variables': {},
        'toolchain': ''
    }
    arch, conf, evidence = detector.detect(extracted)
    assert arch == 'LP64'
    assert conf > 0.9
    print("✓ Architecture detector test passed (LP64)")


def test_time_t_detector():
    """Test time_t size detection."""
    detector = TimeTConfigDetector()
    
    # Test with explicit _TIME_BITS=64
    extracted = {
        'cflags': ['-D_TIME_BITS=64'],
        'defines': [],
        'variables': {}
    }
    size, conf, evidence = detector.detect(extracted)
    assert size == 64
    assert conf > 0.9
    print("✓ time_t detector test passed (64-bit)")
    
    # Test with architecture inference
    extracted = {
        'cflags': [],
        'defines': [],
        'variables': {}
    }
    size, conf, evidence = detector.detect(extracted, architecture='LP64')
    assert size == 64
    assert conf > 0.6
    print("✓ time_t detector test passed (inference)")


def test_full_detection():
    """Test full detection pipeline."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        
        # Create a test Makefile
        makefile = tmp_path / "Makefile"
        makefile.write_text("""
CC = arm-none-eabi-gcc
CFLAGS = -m32 -D_TIME_BITS=32
""")
        
        detector = ConfigDetector(tmp_path)
        results = detector.detect()
        
        assert results['architecture'] == 'ILP32'
        assert results['time_t_size'] == 32
        assert len(results['likelihoods']) == 4
        
        # Check that LP64 configs are ruled out
        lp64_configs = [l for l in results['likelihoods'] if l.name.startswith('lp64')]
        assert all(l.ruled_out for l in lp64_configs)
        
        # Check that ILP32 configs are not ruled out
        ilp32_configs = [l for l in results['likelihoods'] if l.name.startswith('ilp32')]
        assert all(not l.ruled_out for l in ilp32_configs)
        
        print("✓ Full detection pipeline test passed")


if __name__ == '__main__':
    print("Running config_detector Phase 1 tests...")
    print("=" * 50)
    
    try:
        test_makefile_parser()
        test_cmake_parser()
        test_architecture_detector()
        test_time_t_detector()
        test_full_detection()
        
        print("=" * 50)
        print("All tests passed! ✓")
        sys.exit(0)
    except AssertionError as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
