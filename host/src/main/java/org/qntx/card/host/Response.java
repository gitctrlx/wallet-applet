// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

/** The inner result of a §8.4 response record: payload data and the inner status word. */
public record Response(byte[] data, int sw) {}
