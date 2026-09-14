# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""DefineScanner should filter hardware-oriented #defines."""

from __future__ import annotations

import pytest

from tacs.core.define_scanner import DefineScanner


HARDWARE_CASES = [
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
    "#define CLOCK_FREQUENCY_100MHZ     100000000",
    "#define TIMER_PRESCALER_64         64",
    "#define DELAY_COUNTER_1000         1000",
]

Y2038_CASES = [
    ("#define MY_TIME_T time_t", "time_type_alias"),
    ("#define MY_CLOCK_FUNC clock_gettime", "time_function_alias"),
    ("#define MY_TIMESPEC struct timespec", "time_struct_alias"),
    ("#define SECONDS_PER_MINUTE 60", "time_constant"),
    ("#define TIMEOUT_SECONDS 60", "time_constant"),
]


@pytest.mark.parametrize("line", HARDWARE_CASES)
def test_hardware_defines_are_filtered(line: str) -> None:
    scanner = DefineScanner()
    assert scanner.scan_line_for_defines(line, "test.c", 1) == []


@pytest.mark.parametrize("line,expected_type", Y2038_CASES)
def test_y2038_defines_still_match(line: str, expected_type: str) -> None:
    scanner = DefineScanner()
    matches = scanner.scan_line_for_defines(line, "test.c", 1)
    assert len(matches) == 1
    assert matches[0].subcheck_type == expected_type
