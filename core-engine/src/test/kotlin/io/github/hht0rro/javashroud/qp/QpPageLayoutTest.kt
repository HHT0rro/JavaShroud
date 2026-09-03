package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.qp.QpPageLayout
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class QpPageLayoutTest {
    @Test
    fun `current layout variant uses the neutral Qp marker and round trips`() {
        val marker = byteArrayOf(9, 8, 7, 6, 5, 4, 3, 2)
        val layout = QpPageLayout.fromVariant("qp-page-layout:unit:12:8:head:CQgHBgUEAwI")

        assertEquals("qp-page-layout:unit:12:8:head:CQgHBgUEAwI", layout.variant)
        assertEquals("unit", layout.family)
        assertEquals(12, layout.prefixLength)
        assertEquals(8, layout.suffixLength)
        assertTrue(!layout.headerAfterBody)
        assertContentEquals(marker, layout.routingMarker)
    }

    @Test
    fun `retired layout marker fails closed`() {
        val retiredPrefix = byteArrayOf(
            0x61, 0x6B, 0x65, 0x6E, 0x34, 0x2D, 0x66, 0x72, 0x61, 0x6D, 0x65, 0x31,
        ).toString(Charsets.US_ASCII)
        assertFailsWith<IllegalArgumentException> {
            QpPageLayout.fromVariant("$retiredPrefix:unit:12:8:head:CQgHBgUEAwI")
        }
    }
}
