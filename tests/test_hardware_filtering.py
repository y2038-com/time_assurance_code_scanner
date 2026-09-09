#!/usr/bin/env python3
"""
Test script to verify the improved hardware filtering.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tacs.core.define_scanner import DefineScanner

def test_hardware_filtering():
    """Test that hardware-related #defines are properly filtered out."""
    print("Testing Hardware Filtering")
    print("=" * 50)
    
    scanner = DefineScanner()
    
    # Test cases - these should be FILTERED OUT (hardware-related)
    hardware_cases = [
        "#define RCAR_I2C_ICCCR          0x18    /* Clock Control Register */",
        "#define NPCX_ITIM_CLK_SEL_DELAY 92 /* Delay for clock selection (Unit:us) */",
        "#define SDMMC_FREQ_DEFAULT   20000 /*!< SD/MMC Default speed (limited by clock divider) */",
        "#define XUARTPS_MR_CCLK             0x00000400U /**< Input clock select */",
        "#define GPIO_PIN_5                  5",
        "#define I2C_BUS_SPEED              100000",
        "#define SPI_FREQUENCY              1000000",
        "#define UART_BAUD_RATE             115200",
        "#define DMA_CHANNEL_0               0",
        "#define INTERRUPT_PRIORITY         3",
        "#define POWER_VOLTAGE_3V3          3300",
        "#define TEMP_SENSOR_OFFSET         25",
        "#define CLOCK_FREQUENCY_100MHZ     100000000",  # Hardware clock freq
        "#define TIMER_PRESCALER_64         64",         # Hardware timer
        "#define DELAY_COUNTER_1000         1000",       # Hardware delay counter
    ]
    
    # Test cases - these should MATCH (Y2038-relevant)
    y2038_cases = [
        "#define MY_TIME_T time_t",
        "#define MY_CLOCK_FUNC clock_gettime",
        "#define MY_TIMESPEC struct timespec",
        "#define SECONDS_PER_MINUTE 60",
        "#define TIMEOUT_SECONDS 30",
        "#define SLEEP_DELAY_MS 1000",
        "#define WAIT_INTERVAL 500",
        "#define HOURS_PER_DAY 24",
        "#define MINUTES_PER_HOUR 60",
        "#define DAYS_PER_WEEK 7",
    ]
    
    print("Testing hardware cases (should be FILTERED OUT):")
    hardware_matches = 0
    for line in hardware_cases:
        matches = scanner.scan_line_for_defines(line, "test.c", 1)
        if matches:
            print(f"❌ UNEXPECTED MATCH: {line}")
            for match in matches:
                print(f"   -> {match.subcheck_type}: {match.macro_name}")
            hardware_matches += len(matches)
        else:
            print(f"✅ CORRECTLY FILTERED: {line}")
    
    print(f"\nHardware matches found: {hardware_matches} (should be 0)")
    
    print("\nTesting Y2038 cases (should MATCH):")
    y2038_matches = 0
    for line in y2038_cases:
        matches = scanner.scan_line_for_defines(line, "test.c", 1)
        if matches:
            print(f"✅ CORRECTLY MATCHED: {line}")
            for match in matches:
                print(f"   -> {match.subcheck_type}: {match.macro_name}")
            y2038_matches += len(matches)
        else:
            print(f"❌ UNEXPECTED FILTER: {line}")
    
    print(f"\nY2038 matches found: {y2038_matches} (should be > 0)")
    
    print(f"\nSummary:")
    print(f"  Hardware filtering: {'✅ PASS' if hardware_matches == 0 else '❌ FAIL'}")
    print(f"  Y2038 detection: {'✅ PASS' if y2038_matches > 0 else '❌ FAIL'}")

if __name__ == "__main__":
    test_hardware_filtering()
