package com.understory.firewall

import com.understory.security.BaseCapabilityProvider

/**
 * firewall's capability beacon. Consumers translate
 * `(com.understory.firewall, version=1)` into [SuiteCapability.NETWORK_FILTER]
 * via their KNOWN_PEERS table.
 */
class SuiteCapsProvider : BaseCapabilityProvider() {
    override val providedVersion: Int = 1
}
